import {readFile, writeFile, mkdir, rm} from 'node:fs/promises';
import {createPrivateKey, createPublicKey, createHash} from 'node:crypto';

// The optional decoder key is retained only for previously shared e1 links.
// New compressed links and the downloadable HTML do not need it.
try {
  const config = JSON.parse(process.env.COPYTOURL_RECEIVER_KEY ?? '');
  const privateKey = createPrivateKey({format:'jwk', key:config.jwk});
  const jwk = createPublicKey(privateKey).export({format:'jwk'});
  const raw = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const kid = createHash('sha256').update(raw).digest('hex').slice(0, 16);
  if (config.kid !== kid || jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw Error();
  const paths = ['index.html', 'create/index.html', 'copytourl.html', 'copytourl/index.html', 'copytourl/create/index.html', 'copytourl/copytourl.html'];
  const viewerPaths = new Set(['index.html', 'copytourl/index.html']);
  const receiverMarker = 'const RECEIVER = /* receiver-key */ null;';
  const receiver = JSON.stringify({kid, jwk:privateKey.export({format:'jwk'})}).replace(/</g, '\\u003c');
  const prepared = new Map();
  for (const path of paths) {
    const html = await readFile(path, 'utf8');
    const match = /const RECIPIENT = (.+);/.exec(html);
    const publicConfig = JSON.parse(match?.[1] ?? '');
    if (publicConfig.kid !== kid || JSON.stringify(publicConfig.jwk) !== JSON.stringify(jwk) ||
        html.includes(config.jwk.d) || html.split(receiverMarker).length !== 2 ||
        !html.includes("connect-src 'none'")) throw Error();
    prepared.set(path, viewerPaths.has(path) ? html.replace(receiverMarker, `const RECEIVER = ${receiver};`) : html);
  }
  // Remove stale key endpoints or files from previous builds.
  await rm('_site', {recursive:true, force:true});
  await mkdir('_site/copytourl', {recursive:true});
  // Explicit allowlist prevents copying secrets, .git, or build scripts into Pages.
  for (const path of paths) {
    await mkdir(new URL('.', new URL(path, `file://${process.cwd()}/_site/`)), {recursive:true});
    await writeFile(`_site/${path}`, prepared.get(path), {mode:viewerPaths.has(path) ? 0o600 : 0o644});
  }
  await writeFile('_site/.nojekyll', '');
  await writeFile('_site/robots.txt', 'User-agent: *\nDisallow: /\n');
  console.log('Pages 파일 준비 완료. 이전 링크 호환 설정을 웹 열람 페이지에 적용했습니다.');
} catch {
  // Never log exception objects or input that could contain secret key material.
  console.error('배포 키와 공개 HTML을 확인해 주세요. 배포 파일을 만들지 못했습니다.');
  process.exitCode = 1;
}
