import type {
  IndependentFileSmall,
  Plugin,
  PluginAPI,
  SavedSslData,
  SslData,
} from "@lumeweb/relay-types";
import { intervalToDuration } from "date-fns";
import acme from "acme-client";
import cron from "node-cron";
import { sprintf } from "sprintf-js";

const FILE_ACCOUNT_KEY_NAME = "/lumeweb/relay/account.key";

const plugin: Plugin = {
  name: "letsencrypt-ssl",
  async plugin(api: PluginAPI): Promise<void> {
    await bootup(api);
    cron.schedule("0 * * * *", async () => check(api));
  },
};

async function bootup(api: PluginAPI) {
  return check(api, true);
}

async function check(api: PluginAPI, boot = false) {
  let [sslData, error] = await isSslValid(api, boot);
  sslData = sslData as SavedSslData;
  if (!error) {
    api.ssl.set(
      sslData.cert as IndependentFileSmall,
      sslData.key as IndependentFileSmall
    );
    if (boot) {
      let configDomain = api.config.str("domain");
      api.logger.info(`Loaded SSL Certificate for ${configDomain}`);
    }
    return;
  }

  await createOrRenewSSl(api, sslData.cert, sslData.key);
}

async function isSslValid(
  api: PluginAPI,
  boot: boolean
): Promise<[SavedSslData, boolean]> {
  let sslData = await api.ssl.getSaved(boot);
  let domainValid = false;
  let dateValid = false;
  let configDomain = api.config.str("domain");

  if (sslData) {
    let certInfo = await acme.forge.readCertificateInfo(
      Buffer.from((sslData as SavedSslData).cert?.fileData as Uint8Array)
    );
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
      Boolean(isSSlStaging(api)) !==
      Boolean(certInfo?.issuer.commonName.toLowerCase().includes("staging"))
    ) {
      domainValid = false;
    }

    if (dateValid && domainValid) {
      return [sslData as SavedSslData, false];
    }
  }

  if (!sslData) {
    // @ts-ignore
    sslData = { cert: true, key: true };
  }

  return [sslData as SavedSslData, true];
}

async function createOrRenewSSl(api: PluginAPI, oldCert?: any, oldKey?: any) {
  const existing = oldCert && oldKey;

  api.logger.info(
    sprintf(
      "%s SSL Certificate for %s",
      existing ? "Renewing" : "Creating",
      api.config.str("domain")
    )
  );

  let accountKey: boolean | any = await getSslFile(api, FILE_ACCOUNT_KEY_NAME);

  if (accountKey) {
    accountKey = Buffer.from(accountKey.fileData);
  }

  if (!accountKey) {
    accountKey = await acme.forge.createPrivateKey();
    await api.files.createIndependentFileSmall(
      api.getSeed(),
      FILE_ACCOUNT_KEY_NAME,
      accountKey
    );
  }

  let acmeClient = new acme.Client({
    accountKey: accountKey as Buffer,
    directoryUrl: isSSlStaging(api)
      ? acme.directory.letsencrypt.staging
      : acme.directory.letsencrypt.production,
  });

  const [certificateKey, certificateRequest] = await acme.forge.createCsr({
    commonName: api.config.str("domain"),
  });

  let cert: string | Buffer;
  try {
    cert = await acmeClient.auto({
      csr: certificateRequest,
      termsOfServiceAgreed: true,
      challengeCreateFn: async (authz, challenge, keyAuthorization) => {
        api.appRouter
          .get()
          .get(
            `/.well-known/acme-challenge/${challenge.token}`,
            (req: any, res: any) => {
              res.send(keyAuthorization);
            }
          );
      },
      challengeRemoveFn: async () => {
        api.appRouter.reset();
      },
      challengePriority: ["http-01"],
    });
    cert = Buffer.from(cert);
  } catch (e: any) {
    console.error((e as Error).message);
    process.exit(1);
  }

  api.ssl.set(cert, certificateKey);
  await api.ssl.save();
}

function isSSlStaging(api: PluginAPI) {
  return api.config.str("ssl-mode") === "staging";
}

async function getSslFile(
  api: PluginAPI,
  name: string
): Promise<any | boolean> {
  let seed = api.getSeed();

  let [file, err] = await api.files.openIndependentFileSmall(seed, name);

  if (err) {
    return false;
  }

  return file;
}

export default plugin;
