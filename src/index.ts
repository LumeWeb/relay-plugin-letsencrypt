import type { Plugin, PluginAPI } from "@lumeweb/interface-relay";
import { intervalToDuration } from "date-fns";
import acme, { Authorization } from "acme-client";
import cron from "node-cron";
import { sprintf } from "sprintf-js";
import { Mutex } from "async-mutex";
import fs from "fs";
import path from "path";
import { Challenge } from "acme-client/types/rfc8555.js";
import { ca, tr } from "date-fns/locale";
import { FastifyInstance } from "fastify";

const renewMutex = new Mutex();
let configDir: string;
let sslKeyPath: string;
let sslCertPath: string;
let sslCert: string;
let sslKey: string;
let sslCsr: Buffer;
let client: acme.Client;

const acmeChallenges = new Map<string, string>();

const plugin: Plugin = {
  name: "letsencrypt",
  async plugin(api: PluginAPI): Promise<void> {
    configDir = path.join(api.config.str("core.confdir"), "letsencrypt");
    sslKeyPath = path.join(configDir, "ssl.key");
    sslCertPath = path.join(configDir, "ssl.cert");

    if (!fs.existsSync(configDir)) {
      await fs.promises.mkdir(configDir);
    }

    try {
      if (fs.existsSync(sslCertPath)) {
        sslCert = (await fs.promises.readFile(sslCertPath)).toString("utf-8");
        api.ssl.cert = acme.crypto.splitPemChain(sslCert);
      }
      if (fs.existsSync(sslKeyPath)) {
        sslKey = (await fs.promises.readFile(sslKeyPath)).toString("utf-8");
        // @ts-ignore
        api.ssl.privateKey = sslKey;
      }
    } catch {
      sslCert = undefined as any;
      sslKey = undefined as any;
    }

    client = new acme.Client({
      accountKey: await acme.crypto.createPrivateKey(),
      directoryUrl: api.pluginConfig.bool("staging")
        ? acme.directory.letsencrypt.staging
        : acme.directory.letsencrypt.production,
    });

    api.config.set("core.ssl", true);
    // @ts-ignore
    api.ssl.renewHandler = check.bind(undefined, api);

    api.waitFor("core.appServer.buildRoutes").then(() => {
      api.app.get(
        "/.well-known/acme-challenge/:token",
        // @ts-ignore
        (req: any, res: any) => {
          if (acmeChallenges.has(req.params.token)) {
            res.send(acmeChallenges.get(req.params.token));
            return;
          }
          res.code(404);
          res.send();
        }
      );
      check(api);
      cron.schedule("0 * * * *", async () => check(api));
    });
  },
};

async function check(api: PluginAPI) {
  if (!sslCert || !sslKey) {
    return renew(api);
  }

  let domainValid = false;
  let dateValid = false;
  // @ts-ignore
  let configDomain = api.ssl.domain;

  let certInfo = await acme.forge.readCertificateInfo(sslCert);
  const expires = certInfo?.notAfter as Date;
  let duration = intervalToDuration({ start: new Date(), end: expires });
  let daysLeft = (duration.months as number) * 30 + (duration.days as number);

  if (daysLeft > 30) {
    dateValid = true;
  }

  if (certInfo?.domains.commonName === configDomain) {
    domainValid = true;
  }

  if (
    isSSlStaging(api) !==
    Boolean(certInfo?.issuer.commonName.toLowerCase().includes("staging"))
  ) {
    domainValid = false;
  }

  if (dateValid && domainValid) {
    return;
  }

  return renew(api);
}

async function renew(api: PluginAPI) {
  await renewMutex.acquire();
  const result = await client.auto({
    challengeCreateFn(
      authz: Authorization,
      challenge: Challenge,
      keyAuthorization: string
    ): Promise<void> {
      acmeChallenges.set(challenge.token, keyAuthorization);
      return Promise.resolve();
    },
    challengeRemoveFn(
      authz: Authorization,
      challenge: Challenge,
      keyAuthorization: string
    ): Promise<void> {
      acmeChallenges.delete(challenge.token);
      return Promise.resolve();
    },
    csr: await generateCsr(api),
    termsOfServiceAgreed: true,
  });

  await fs.promises.writeFile(sslCertPath, result);
  // @ts-ignore
  api.ssl.cert = undefined;
  api.ssl.privateKey = undefined as any;
  api.ssl.cert = acme.crypto.splitPemChain(result);
  // @ts-ignore
  api.ssl.privateKey = sslKey;

  renewMutex.release();
}

async function generateCsr(api: PluginAPI) {
  let key: Buffer;
  [key, sslCsr] = await acme.crypto.createCsr({
    // @ts-ignore
    commonName: api.ssl.domain,
  });

  sslKey = key.toString("utf-8");

  await fs.promises.writeFile(sslKeyPath, sslKey);

  return sslCsr;
}

function isSSlStaging(api: PluginAPI) {
  return api.pluginConfig.bool("staging");
}

export default plugin;
