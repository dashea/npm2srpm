#!/usr/bin/node

// npm2srpm.js - generate SRPM packages from npm modules
// Copyright (C) 2018 David Shea <dshea@redhat.com>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

const childProcess = require('child_process');
const csvParseSync = require('csv-parse/lib/sync');
const dateformat = require('dateformat');
const diff = require('diff');
const fetch = require('node-fetch');
const fs = require('fs');
const handlebars = require('handlebars');
const npmFetch = require('npm-registry-fetch');
const path = require('path');
const readPackageJSON = require('read-package-json');
const semver = require('semver');
const spdxCorrect = require('spdx-correct');
const spdxParse = require('spdx-expression-parse');
const ssri = require('ssri');
const streamToPromise = require('stream-to-promise');
const tar = require('tar');
const tmp = require('tmp');
const url = require('url');
const yargs = require('yargs');

const npmClientConf = { timeout: 1000 };

tmp.setGracefulCleanup();

// load the specfile template
const templateFile = 'specfile.hjs';
const templateData = fs.readFileSync(path.join(__dirname, templateFile), { encoding: 'utf-8' });
const template = handlebars.compile(templateData);

// load the license string CSV
const csvFile = 'spdx_to_fedora.csv';
const csvData = fs.readFileSync(path.join(__dirname, csvFile));
const licenseRecords = csvParseSync(csvData, { columns: true });

function readPackageJSONPromise(packageJSONPath) {
  return new Promise((resolve, reject) => {
    readPackageJSON(packageJSONPath, (err, packageData) => {
      if (err) {
        reject(err);
      } else {
        resolve(packageData);
      }
    });
  });
}

// Normalize arguments that are expected multiple times into an array
// If the argument is specified 0 times, yargs will set undefined,
// if the argument is specified 1 time, yargs will set the type of the
// argument (string, boolean, etc), and if more than 1 time yargs will set an array.
// Make all of these cases an array.
function normalizeArgList(opt) {
  if (typeof (opt) === 'undefined') {
    return [];
  }

  if (Array.isArray(opt)) {
    return opt;
  }

  return [opt];
}

// Enforce that an argument is specified only 0 or 1 times
function enforceSingleArg(opt, optName) {
  if (!((typeof (opt) === 'undefined') || !Array.isArray(opt))) {
    throw new Error(`${optName} can only specified once`);
  }
}

function unpackTarball(tarball, dest) {
  return tar.x({ file: tarball, cwd: dest });
}

function encodeModuleName(moduleName) {
  // handle npm's weird module name encoding: '/' is a legal
  // character, and it (and only it) should be URI-encoded (as %2F).
  return moduleName.replace(/\//g, '%2F');
}

function spdxExpressionToFedora(expr) {
  if ('conjunction' in expr) {
    // try to find matches for each half
    const leftLicense = spdxExpressionToFedora(expr.left);
    const rightLicense = spdxExpressionToFedora(expr.right);

    if (expr.conjunction === 'and') {
      // if either side is null, we cannot continue
      if (leftLicense === null || rightLicense === null) {
        return null;
      }

      return `(${leftLicense} and ${rightLicense})`;
    }

    // if both sides are null, we cannot continue
    if (leftLicense === null && rightLicense === null) {
      return null;
    }

    // if one is null, just return the other
    if (leftLicense === null) {
      return rightLicense;
    }
    if (rightLicense === null) {
      return leftLicense;
    }
    return `(${leftLicense} or ${rightLicense})`;
  }

  // Find the SPDX license in the CSV data
  const spdxMatch = licenseRecords.filter(rec => rec['SPDX License Identifier'] === expr.license);
  if (spdxMatch.length === 0) {
    // unsupported license
    return null;
  }
  if (spdxMatch.length > 1) {
    // data error
    throw new Error(`More than one license found for ${expr.license}`);
  }

  const fedoraName = spdxMatch[0]['Fedora Short Name'];
  if (!fedoraName) {
    return null;
  }

  return fedoraName;
}

function spdxToFedora(packageData) {
  let licenseString;
  if ('license' in packageData) {
    if (typeof (packageData.license) === 'object') {
      licenseString = packageData.license.type;
    } else {
      licenseString = packageData.license;
    }
  } else if ('licenses' in packageData) {
    licenseString = packageData.licenses.map(license => license.type).join(' or ');
  } else {
    throw new Error('No license data found');
  }

  const fedoraLicense = spdxExpressionToFedora(spdxParse(spdxCorrect(licenseString)));
  if (fedoraLicense === null) {
    throw new Error(`No Fedora equivalent found for ${licenseString}`);
  }

  return fedoraLicense;
}

// convert one part of a semver range (i.e., >=1.2.3) to a RPM dep expression
function constraintToBuildReq(depName, constraint) {
  // If the contraint is "*", there is no version, so just return the
  // requirement name. If the contraint starts with '>' or '<'
  // (which includes '>=' and '<=', use it as-is. Otherwise, it's a single
  // version and we want a RPM requirement of '= <version>'.
  const reqName = `npmlib(${depName})`;

  if (constraint === '*') {
    return reqName;
  }

  if (constraint.startsWith('>') || constraint.startsWith('<')) {
    // add a space between the operator and the version number
    const constraintSpace = constraint
      .replace(/^>=/, '>= ')
      .replace(/^>([^=])/, '> $1')
      .replace(/^<=/, '<= ')
      .replace(/^<([^=])/, '< $1')
      .replace(/^=/, '= ');

    return `${reqName} ${constraintSpace}`;
  }

  return `${reqName} = ${constraint}`;
}

function depToBuildReq(depName, depVersion) {
  // Normalize(ish) the version
  const versionRange = semver.validRange(depVersion);

  // If versionRange returned null, something went wrong
  if (versionRange === null) {
    throw new Error(`Invalid version range for ${depName}: ${depVersion}`);
  }

  // result of validRange is now a DNF expression,
  // converted to a string as 'a b||c d', with spaces
  // being AND and || being OR. Split all of that back apart.
  const versionDNF = versionRange.split('||').map(s => s.split(' '));

  // convert each of the version units to an RPM expression
  const buildReqDNF = versionDNF
    .map(andExp => andExp.map(exp => constraintToBuildReq(depName, exp)));

  // for each of the AND clauses (the inner expressions), we want to
  // convert 'a AND b' into 'a with b'.
  // Each of the OR expressions just becomes 'a or b'.
  // wrap the whole thing in parenthesis to tell RPM it's a boolean dep
  const rpmExpression = `(${buildReqDNF.map(andExp => `(${andExp.join(' with ')})`)
    .join(' or ')})`;

  // wrap the whole thing in an object for the template
  return { buildRequiresExp: rpmExpression };
}

function mapBin(bin) {
  if (!bin) {
    return [];
  }

  return Object.entries(bin)
    .map(([binPath, modulePath]) => ({ modulePath: path.normalize(modulePath), binPath }));
}

// split up man pages by section
function mapMan(tmpPath, man) {
  // start with an object indexed by section number, each section number
  // containing an array of man pages in that section
  // e.g., {"1": ['./man/cool-program.1', './man/lame-program.1.gz'],
  //        "5": ['./man/cool-program.conf.5']}
  const manSections = {};
  if (man) {
    man.forEach((s) => {
      const sectionMatch = s.match(/\.([0-9]+)(\.gz)?$/);
      if (sectionMatch === null) {
        throw new Error(`Invalid man page name: ${s}`);
      }

      const section = sectionMatch[1];
      if (!(section in manSections)) {
        manSections[section] = [];
      }
      manSections[section].push(s);
    });
  }

  // convert that into something more usable by the template
  // [ {manSection: "1", manPages: [{modulePath: './man/cool-program.1',
  //                                 manPath: 'cool-program.1',
  //                                 compressed: false},
  //                                {modulePath: './man/lame-program.1',
  //                                 manPath: 'lame-program.1.gz',
  //                                 compressed: true}] },
  //   {manSection: "5", manPages: [{modulePath: './man/cool-program.conf.5',
  //                                 manPath: 'cool-program.conf.5',
  //                                 compressed: false}]}]
  return Object.entries(manSections).map(([section, files]) => ({
    manSection: section,
    manPages: files.map((f) => {
      // if the man object was generated from directories.man, it's full of absolute
      // paths. We need those to be relative to the package directory.
      let modulePath = path.normalize(f);
      if (path.isAbsolute(modulePath)) {
        modulePath = path.relative(path.join(tmpPath, 'package'), modulePath);
      }
      return { modulePath, manPath: path.basename(f), compressed: f.endsWith('.gz') };
    }),
  }));
}

// "fix" any python shebang lines. return a list of generated patch files.
// All patch files will be created at -p0
// Any unversioned python #! will be replaced with python2, since that's what
// node-gyp supports currently.
function patchShebang(tmpPath, modulePath) {
  let patchIndex = 0;

  function patchShebangHelper(currentDir) {
    const fileList = fs.readdirSync(path.join(modulePath, currentDir));
    return fileList.reduce((acc, fileName) => {
      const filePath = path.join(modulePath, currentDir, fileName);
      const stat = fs.lstatSync(filePath);

      // if it's a directory, recurse
      if (stat.isDirectory()) {
        return acc.concat(patchShebangHelper(path.join(currentDir, fileName)));
      }

      // If it's a regular file, look for an unversioned python shebang to patch.
      // Use latin1 for everything since all we care about is the shebang, which
      // won't have 8-bit characters (we're assuming BOM is illegal), and that
      // way we can't have encode/decode errors on the rest of the file
      if (stat.isFile()) {
        const origData = fs.readFileSync(filePath, { encoding: 'latin1' });
        // match on #!, optional whitespace, and either "[/usr]/bin/python" (unversioned),
        // or "[/usr]/bin/env python"
        const match = origData.match(/^#!\s*(((\/usr)?\/bin\/python)|((\/usr)?\/bin\/env python))\b/);
        if (match) {
          // replace the matched string with "#!/usr/bin/python2"
          const newData = `#!/usr/bin/python2${origData.slice(match[0].length)}`;
          const diffData = diff.createPatch(path.join(currentDir, fileName), origData, newData);
          const patchPath = path.join(tmpPath, `npm2srpm-shebang-patch-${patchIndex}.patch`);
          patchIndex += 1;

          fs.writeFileSync(patchPath, diffData, { encoding: 'latin1' });
          return acc.concat([path.basename(patchPath)]);
        }

        return acc;
      }

      // otherwise, do nothing
      return acc;
    }, []);
  }

  return patchShebangHelper('.');
}

async function fetchVersion(tmpPath, moduleName, versionMatch) {
  const uri = `/${encodeModuleName(moduleName)}`;
  let versions;
  let version = null;

  const registryData = await npmFetch.json(uri);

  // find a matching version
  // start with the dist-tags
  if (versionMatch in registryData['dist-tags']) {
    version = registryData['dist-tags'][versionMatch];
  } else {
    // Otherwise, treat versionMatch as a semver expression and look
    // for the greatest match
    versions = Object.keys(registryData.versions);
    version = semver.maxSatisfying(versions, versionMatch);
  }

  if (version === null) {
    throw new Error(`No version available for ${moduleName} matching ${versionMatch}`);
  }

  // parse the URL to get the filename
  const versionData = registryData.versions[version];
  const tarballName = new url.URL(versionData.dist.tarball).pathname.split('/').pop();

  const outputPath = path.join(tmpPath, tarballName);
  const outputStream = fs.createWriteStream(outputPath);
  const outputPromise = streamToPromise(outputStream);

  // parse the checksum data into an integrity object
  // if no ssri data is available, convert the shasum property
  let integrity;
  if (versionData.dist.integrity) {
    integrity = ssri.parse(versionData.dist.integrity);
  } else {
    integrity = ssri.fromHex(versionData.dist.shasum, 'sha1');
  }

  const integrityStream = ssri.integrityStream({ integrity });
  const integrityPromise = streamToPromise(integrityStream);

  // fetch the tarball and pipe it to both the integrity checker and the filesystem
  await fetch(versionData.dist.tarball)
    .then((res) => {
      const promise = streamToPromise(res.body);
      res.body.pipe(outputStream);
      res.body.pipe(integrityStream);
      return promise;
    });

  // make sure both the write streams complete
  await Promise.all([outputPromise, integrityPromise]);

  // return the tarball path and the object from the registry
  return {
    tarball: outputPath,
    versionData,
  };
}

async function makeSRPM(tmpPath, sourceUrl, sourceDir, modulePath, opts) {
  const packageJSONPath = path.join(modulePath, 'package.json');

  // If there are deps to force, add those the package.json first
  let depPatch = null;
  if (opts.addDeps) {
    // Read the original package.json file
    const packageJSONOrig = fs.readFileSync(packageJSONPath, { encoding: 'latin1' });
    const packageJSONData = JSON.parse(packageJSONOrig);

    // initialize the dependencies object if there are none already
    if (!('dependencies' in packageJSONData)) {
      packageJSONData.dependencies = {};
    }

    opts.addDeps.forEach((dep) => {
      const depSplit = dep.split('@');
      const depName = depSplit[0];
      let [, depVersion] = depSplit;
      if (depVersion === undefined) {
        depVersion = '*';
      }

      packageJSONData.dependencies[depName] = depVersion;
    });

    // serialize and write out the new package.json
    const packageJSONNew = JSON.stringify(packageJSONData, null, 2);
    fs.writeFileSync(packageJSONPath, packageJSONNew);

    // create a diff and write it to the tmpdir
    const diffData = diff.createPatch('package.json', packageJSONOrig, packageJSONNew);
    depPatch = 'npm2srpm-dependencies.patch';
    fs.writeFileSync(path.join(tmpPath, depPatch), diffData);
  }

  // Read the package.json file
  // use read-package-json to normalize the data
  const packageData = await readPackageJSONPromise(packageJSONPath);

  // if the package has a scope, split that out
  let moduleName;
  let moduleScope;
  if (packageData.name.indexOf('/') !== -1) {
    [moduleScope, moduleName] = packageData.name.split('/');
  } else {
    moduleName = packageData.name;
    moduleScope = '';
  }

  // node-gyp has extra requirements not encoded in package.json.
  // hardcode those here
  let extraRequires = [];
  if (moduleName === 'node-gyp') {
    extraRequires = [
      { requirement: 'python2' },
      { requirement: 'make' },
      { requirement: 'gcc' },
      { requirement: 'gcc-c++' },
    ];
  }

  // convert the dependencies to a list, since after adding bundled module deps
  // there could be repeated names
  let buildRequires;
  if (packageData.dependencies) {
    buildRequires = Object
      .entries(packageData.dependencies)
      .map(([name, version]) => ({ name, version }));
  } else {
    buildRequires = [];
  }

  // normalize-package-data, for some reason, copies whatever is in optionalDependencies
  // to the regular dependencies. Filter them back out.
  if (packageData.optionalDependencies) {
    buildRequires = buildRequires.filter(buildReq => !(buildReq.name in packageData.optionalDependencies));
  }

  // fetch the tarballs for any additional deps to bundle, add their dependencies
  // to the buildrequires.
  // start indexes at 1, since the main source is Source0
  let bundledSources = [];
  if (opts.bundledDeps) {
    const results = opts.bundledDeps.map(async (dep, idx) => {
      const fetchObj = await fetchVersion(tmpPath, dep.name, dep.version);

      if (fetchObj.versionData.dependencies) {
        Object.entries(fetchObj.versionData.dependencies).forEach(([name, version]) => {
          buildRequires.push({ name, version });
        });
      }

      return { idx: idx + 1, tarball: fetchObj.versionData.dist.tarball, name: dep.name };
    });
    bundledSources = await Promise.all(results);

    function isDepMatch(bundledDep, buildReq) { /* eslint-disable-line no-inner-declarations */
      return ((bundledDep.name === buildReq.name) && (semver.satisfies(bundledDep.version, buildReq.version)));
    }

    // filter out the bundled deps from the buildRequires
    opts.bundledDeps.forEach((bundledDep) => {
      buildRequires = buildRequires.filter(buildReq => !isDepMatch(bundledDep, buildReq));
    });

    // filter the main module out of the buildRequires, in case that got added from a dependency loop
    buildRequires = buildRequires.filter(buildReq => !isDepMatch({ name: packageData.name, version: packageData.version }, buildReq));
  }

  const cleanModuleName = packageData.name.replace(/\//g, '-').replace(/@/g, '');
  const packageName = `npmlib-${cleanModuleName}`;

  // Read the package directory for the top-level filenames, split them
  // up by license, doc, other
  const packageList = fs.readdirSync(modulePath);
  const docList = [];
  const licenseList = [];
  const fileList = [];

  packageList.forEach((fileName) => {
    // ignore node_modules if present
    if (fileName !== 'node_modules') {
      if (fileName.match(/\.txt$|\.md$|authors|readme|contributing|docs/i)) {
        docList.push({ docName: fileName });
      } else if (fileName.match(/license|copying/i)) {
        licenseList.push({ licenseName: fileName });
      } else {
        fileList.push({ fileName });
      }
    }
  });

  // if no homepage is present in package.json, try repo
  let packageUrl;
  if (packageData.homepage) {
    packageUrl = packageData.homepage;
  } else if (packageData.repository) {
    packageUrl = packageData.repository.url;
  } else {
    packageUrl = null;
  }

  const manList = mapMan(tmpPath, packageData.man);
  // whether any man pages included in npm-library are compressed
  const compressedManPages = manList
    .some(section => section.manPages.some(page => page.compressed));

  let license;
  if (opts.forceLicense) {
    license = opts.forceLicense;
  } else {
    license = spdxToFedora(packageData);
  }

  const patchlist = patchShebang(tmpPath, modulePath);
  if (depPatch) {
    patchlist.push(depPatch);
  }

  let installScript = '';
  if (('scripts' in packageData) && ('install' in packageData.scripts)) {
    installScript = packageData.scripts.install;
  }

  // only node-gyp is supported for binary packages
  const binary = fs.existsSync(path.join(modulePath, 'binding.gyp'));

  let check = true;
  // see if %check is explicitly disabled
  if (opts.disableCheck) {
    check = false;
  // skip %check if this package has peer dependencies, since those won't be installed
  } else if ('peerDependencies' in packageData) {
    check = false;
  // if there is no entry point, also skip %check
  // TODO assume binary packages will generate index.node until this blows
  // up and have I figure out something better
  } else if (!('main' in packageData)
      && !fs.existsSync(path.join(modulePath, 'index.js'))
      && !binary) {
    check = false;
  }

  // construct the data for the template
  const specData = {
    name: moduleName,
    scope: moduleScope,
    packageName,
    version: packageData.version,
    release: opts.release,
    summary: packageData.description.split('\n')[0],
    description: packageData.description,
    license,
    url: packageUrl,
    sourceUrl,
    buildRequires: buildRequires.map(dep => depToBuildReq(dep.name, dep.version)),
    binList: mapBin(packageData.bin),
    cldate: dateformat(Date(), 'ddd mmm d yyyy'),
    fileList,
    docList,
    licenseList,
    manList: mapMan(tmpPath, packageData.man),
    compressedManPages,
    patches: patchlist.map((patchName, idx) => ({ patchNum: idx, patchName })),
    extraRequires,
    installScript,
    binary,
    check,
    bundledSources,
  };

  const specFileData = template(specData);
  const specFilePath = `${packageName}.spec`;

  // if only the spec file is requested, just write it to the current directory
  if (opts.specOnly) {
    fs.writeFile(specFilePath, specFileData, { encoding: 'utf-8' }, (writeErr) => {
      if (writeErr) throw writeErr;
      console.log(`Wrote: ${specFilePath}`);
    });
  } else {
    // write the spec file to the tmp directory
    fs.writeFile(path.join(tmpPath, specFilePath), specFileData, { encoding: 'utf-8' }, (writeErr) => {
      if (writeErr) throw writeErr;

      // create an SRPM
      childProcess.execFile('rpmbuild',
        ['-bs',
          '-D', '_srcrpmdir .',
          '-D', `_sourcedir ${sourceDir}`,
          '-D', `_specdir ${tmpPath}`,
          path.join(tmpPath, specFilePath),
        ], (processError, stdout, stderr) => {
          if (processError) {
            console.error(stderr);
            throw processError;
          }

          process.stdout.write(stdout);
          process.stderr.write(stderr);
        });
    });
  }
}

async function processModuleRegistry(moduleName, versionMatch, opts) {
  const tmpPath = tmp.dirSync({ unsafeCleanup: true }).name;
  const fetchObj = await fetchVersion(tmpPath, moduleName, versionMatch);

  await unpackTarball(fetchObj.tarball, tmpPath);

  makeSRPM(
    tmpPath,
    fetchObj.versionData.dist.tarball,
    tmpPath,
    path.join(tmpPath, 'package'),
    opts,
  );
}

async function processModule(moduleName, versionMatch, opts) {
  // if this is a local module, create a new tmp directory,
  // unpack the tarball and skip to makeSRPM
  if (opts.isLocal) {
    const tmpPath = tmp.dirSync({ unsafeCleanup: true }).name;
    await unpackTarball(moduleName, tmpPath);
    makeSRPM(tmpPath,
      path.basename(moduleName),
      path.dirname(moduleName),
      path.join(tmpPath, 'package'),
      opts);
  } else {
    processModuleRegistry(moduleName, versionMatch, opts);
  }
}

async function main() {
  const { argv } = yargs
    .usage('$0 [options] MODULE')
    .option('tag', {
      alias: 't',
      default: 'latest',
      describe: 'Install the given tag or version',
      type: 'string',
    })
    .option('local', {
      type: 'boolean',
      default: false,
      describe: 'Use a local module tarball instead of a npm registry',
    })
    .option('registry', {
      type: 'string',
      describe: 'Base URL of the npm registry to use',
    })
    .coerce('registry', (registry) => {
      // ensure the URL ends with a / so we can append stuff to it
      if (registry.endsWith('/')) {
        return registry;
      }
      return `${registry}/`;
    })
    .option('spec-only', {
      type: 'boolean',
      default: false,
      describe: 'Output only a .spec file instead of a SRPM',
    })
    .option('force-license', {
      type: 'string',
      describe: 'Set the license string to use in the spec file',
    })
    .option('add-dep', {
      type: 'string',
      describe: 'Add a dependency to package.json',
    })
    .option('release', {
      type: 'string',
      default: '1',
      describe: 'Specify the release version to use in the RPM',
    })
    .option('disable-check', {
      type: 'boolean',
      default: false,
      describe: 'Disable %check',
    })
    .option('bundle', {
      type: 'string',
      describe: 'Bundle a dependency (<name>@<version>)',
    })
    // for cli arguments specified multiple times, yargs will create an array of strings.
    // if the argument is only specified once, yargs will create a string.
    // for arguments we expect multiple times, make the type consistent
    .coerce({
      'add-dep': normalizeArgList,
    })
    // do bundle separately since there's more to do than just normalizeArgList
    .coerce('bundle', bundle => normalizeArgList(bundle).map((dep) => {
      // split the bundled deps (name@version) into name, version
      let name;
      let version;

      // if it's a scoped package, the first @ isn't the one we want
      if (dep.startsWith('@')) {
        [name, version] = dep.slice(1).split('@');
        name = `@${name}`;
      } else {
        [name, version] = dep.split('@');
      }

      if (version === undefined) {
        version = 'latest';
      }

      return { name, version };
    }))
    .check((args) => {
      // make sure the arguments that make sense only once are only specified once
      enforceSingleArg(args.tag, '--tag');
      enforceSingleArg(args.local, '--local');
      enforceSingleArg(args.registry, '--registry');
      enforceSingleArg(args['spec-only'], '--spec-only');
      enforceSingleArg(args['force-license'], '--force-license');
      enforceSingleArg(args.release, '--release');
      enforceSingleArg(args['disable-check'], '--disable-check');

      // ensure there is exactly one module name
      if (args._.length === 0) {
        throw new Error('You must specify a module name');
      }

      if (args._.length > 1) {
        throw new Error('Only one module can be specified');
      }

      return true;
    })
    .strict();

  if (argv.registry) {
    npmClientConf.registry = argv.registry;
  }

  const opts = {
    isLocal: argv.local,
    registryUrl: argv.registry,
    specOnly: argv['spec-only'],
    forceLicense: argv['force-license'],
    addDeps: argv['add-dep'],
    release: argv.release,
    disableCheck: argv['disable-check'],
    bundledDeps: argv.bundle,
  };

  await processModule(argv._[0], argv.tag, opts);
}

if (require.main === module) {
  process.on('unhandledRejection', (e) => {
    throw e;
  });
  main();
}
