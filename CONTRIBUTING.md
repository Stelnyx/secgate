```text
░▒▓█ SECGATE · CONTRIBUTING █▓▒░
```

# Contributing to SecGate

Thanks for your interest. SecGate is a security engine — contributions that improve detection fidelity, reduce false positives, or extend CI integration are especially welcome.

## Ground rules

- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Report security issues privately — see [SECURITY.md](SECURITY.md). Never open a public issue for a vulnerability.
- Open an issue before large changes so we can align on scope.

## Development setup

```bash
git clone https://github.com/Stelnyx/SecGate.git
cd SecGate
npm install
node secgate.js --help
```

## Pull request checklist

- [ ] Branch name describes the change (`feat/<slug>`, `fix/<slug>`, `docs/<slug>`)
- [ ] Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`)
- [ ] New detectors or remediations include a short test fixture
- [ ] No secrets, tokens, or real scan artifacts committed
- [ ] README updated if CLI flags or output shape changed

## Releases

One workflow does the whole release: `.github/workflows/release.yml`, triggered
by pushing a `vX.Y.Z` tag. It runs the dependency guard, lint and tests, builds
the tarball and CycloneDX SBOM, generates SLSA provenance, signs both files with
cosign (keyless), creates the GitHub Release with those assets, and then
publishes the same tarball to npm with `npm publish --provenance`.

Do not create the GitHub Release by hand (the workflow creates it), do not store
`NPM_TOKEN` / `NODE_AUTH_TOKEN` secrets, and do not publish from a local machine.
npm authenticates the publish through npm trusted publishing (GitHub OIDC).

Trusted Publisher settings on npmjs.com for `@stelnyx/secgate`:

- Publisher: GitHub Actions
- Organization/user: `Stelnyx`
- Repository: `secgate` (must match the current GitHub repository name)
- Workflow filename: `release.yml`
- Environment: `npm` (the GitHub environment of the `publish-npm` job)

The repository must remain public for npm to show provenance. The package's
`repository` field must keep matching the GitHub repository URL.

Release flow:

1. Bump `package.json` and `package-lock.json` to the next semver version
   (`npm version <x.y.z> --no-git-tag-version`).
2. Move the `[Unreleased]` entries in `CHANGELOG.md` under the new version.
3. Run `npm run check:deps`, `npm run lint`, `npm test` and `npm pack --dry-run`.
   Confirm the dry run includes `CHANGELOG.md` and that `npm ls @stelnyx/report-theme`
   shows a registry version, not a local `-> ../report-theme` symlink.
4. Merge the version bump to `main`.
5. Tag that commit and push the tag, for example
   `git tag v0.2.15 && git push origin v0.2.15`.
6. Watch the `Release` workflow until every job is green.
7. Confirm npm provenance:
   `npm view @stelnyx/secgate@0.2.15 dist.attestations.provenance.predicateType`
   must print `https://slsa.dev/provenance/v1`. Then run `npm audit signatures`
   in a project that installs it.

The workflow refuses to run from a branch, for a tag that is not `vX.Y.Z`, for
a version already on npm, or when a GitHub Release for the tag already exists.
If a later job fails, use "Re-run failed jobs" on the same run so the release
reuses the artifacts that were already built and signed.

A manual run (`workflow_dispatch`) must be started from the tag itself ("Use
workflow from" set to the tag, and the `tag` input equal to it). Use
`skip_npm: true` only to add release assets for a version that is already on
npm; the run fails unless the rebuilt tarball is byte-identical to the one on
npm.

## Commit message format

```
<type>(<scope>): <short description>

<optional body explaining why, not what>
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `security`, `perf`.

## Questions

Open a [discussion](https://github.com/Stelnyx/SecGate/discussions) or a regular issue. Security matters go through private advisory only.
