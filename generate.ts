import { mkdir, writeFile } from 'node:fs/promises';
import {AuthorizationServer} from "oauth4webapi";
import {exportJWK, generateKeyPair, type JWK} from 'jose';
import arg from 'arg';
import { dirname, join } from 'node:path';

const JWK_RELATIVE_PATH = '.well-known/jwks.json';
const CONFIG_RELATIVE_PATH = '.well-known/openid-configuration';

const args = arg({
    '--out-dir': String,
    '--issuer': String,
});

const issuer = args['--issuer'] ?? (() => {throw new Error('Missing --issuer')})();
const outDir = args['--out-dir'] ?? "./dist";

const jwks = await mkJWks();
const configuration = mkAuthServer(issuer);



await Promise.all([
    emit(join(outDir, JWK_RELATIVE_PATH), jwks),
    emit(join(outDir, CONFIG_RELATIVE_PATH), configuration),
]);

async function emit(path: string, data: object) {
    const dir = dirname(path);
    await mkdir(dir, {recursive: true});
    await writeFile(path, JSON.stringify(data));
}

async function mkJWks(): Promise<{keys: JWK[]}> {
    const {privateKey, publicKey} = await generateKeyPair('RS256');
    const jwks = {
        keys: await Promise.all([publicKey, privateKey].map(exportJWK))
    }
    return jwks;
}

function mkAuthServer(issuer: string): AuthorizationServer {
    // Remove any trailing slash
    issuer = issuer.replace(/\/$/, '');
    return {
        issuer,
        jwks_uri: new URL(JWK_RELATIVE_PATH, issuer.replace(/[^/]$/, "$&/")).toString(),
    }
}
