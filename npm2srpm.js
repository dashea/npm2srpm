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
const crypto = require('crypto');
const dateformat = require('dateformat');
const diff = require('diff');
const fs = require('fs');
const handlebars = require('handlebars');
const path = require('path');
const readPackageJSON = require('read-package-json');
const request = require('request');
const semver = require('semver');
const spdxCorrect = require('spdx-correct');
const spdxParse = require('spdx-expression-parse');
const stream = require('stream');
const tar = require('tar-fs');
const tmp = require('tmp');
const url = require('url');
const yargs = require('yargs');
const zlib = require('zlib');
const RegClient = require('silent-npm-registry-client');

const npmClient = new RegClient();
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

function unpackTarball(tarball, dest) {
  const gunzip = zlib.createGunzip();
  return fs.createReadStream(tarball).pipe(gunzip).pipe(tar.extract(dest));
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

function depsToBuildReqs(dep) {
  if (!dep) { return []; }

  return Object.entries(dep).map(([depName, depVersion]) => {
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
  });
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
      const modulePath = path.relative(path.join(tmpPath, 'package'), f);
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
          return acc.concat([patchPath]);
        }

        return acc;
      }

      // otherwise, do nothing
      return acc;
    }, []);
  }

  return patchShebangHelper('.');
}

function makeSRPM(tmpPath, sourceUrl, sourceDir, modulePath, specOnly, forceLicense) {
  // Read the package.json file
  // use read-package-json to normalize the data
  readPackageJSON(path.join(modulePath, 'package.json'), (err, packageData) => {
    if (err) throw err;
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

    const cleanModuleName = packageData.name.replace(/\//g, '-').replace(/@/g, '');
    const packageName = `npmlib-${cleanModuleName}`;

    // Read the package directory for the top-level filenames, split them
    // up by license, doc, other
    fs.readdir(modulePath, (dirErr, packageList) => {
      if (dirErr) throw dirErr;

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
      if (forceLicense) {
        license = forceLicense;
      } else {
        license = spdxToFedora(packageData);
      }

      const patchlist = patchShebang(tmpPath, modulePath);

      let installScript = '';
      if (('scripts' in packageData) && ('install' in packageData.scripts)) {
        installScript = packageData.scripts.install;
      }

      // only node-gyp is supported for binary packages
      const binary = fs.existsSync(path.join(modulePath, 'binding.gyp'));

      // construct the data for the template
      const specData = {
        name: moduleName,
        scope: moduleScope,
        packageName,
        version: packageData.version,
        summary: packageData.description.split('\n')[0],
        description: packageData.description,
        license,
        url: packageUrl,
        sourceUrl,
        buildRequires: depsToBuildReqs(packageData.dependencies),
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
      };

      const specFileData = template(specData);
      const specFilePath = `${packageName}.spec`;

      // if only the spec file is requested, just write it to the current directory
      if (specOnly) {
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
    });
  });
}

function processVersion(moduleName, moduleVersion, registryData, specOnly, forceLicense) {
  // Grab and verify the dist tarball, unpack it
  tmp.dir({ unsafeCleanup: true }, (err, tmpPath) => {
    if (err) throw err;

    const data = registryData.versions[moduleVersion];

    // parse the URL to get the filename
    const tarballName = new url.URL(data.dist.tarball).pathname.split('/').pop();

    const outputPath = path.join(tmpPath, tarballName);
    const outputStream = fs.createWriteStream(outputPath);

    // create a pass-through stream to calculate the SHA1 as we download
    const tee = new stream.PassThrough();
    const hash = crypto.createHash('sha1');
    tee
      .on('data', (chunk) => {
        hash.update(chunk);
        outputStream.write(chunk);
      });

    request(data.dist.tarball).pipe(tee)
      .on('finish', () => {
        const digest = hash.digest('hex');

        // check the hash
        if (digest !== data.dist.shasum) {
          throw new Error(`SHA1 digest for ${moduleName}@${moduleVersion} does not match`);
        }

        // unpack the tarball
        // tarballs from npm will unpack into a 'package' directory
        unpackTarball(outputPath, tmpPath)
          .on('finish', () => {
            makeSRPM(tmpPath, data.dist.tarball, path.dirname(outputPath), path.join(tmpPath, 'package'), specOnly, forceLicense);
          });
      });
  });
}

function processModuleRegistry(moduleName, versionMatch, registryUrl, specOnly, forceLicense) {
  const uri = registryUrl + encodeModuleName(moduleName);
  let versions;
  let version;

  npmClient.get(uri, npmClientConf, (error, data) => {
    if (error) {
      throw error;
    }

    // find a matching version
    // start with the dist-tags
    if (versionMatch in data['dist-tags']) {
      processVersion(moduleName, data['dist-tags'][versionMatch], data, specOnly);
    } else {
      // Otherwise, treat versionMatch as a semver expression and look
      // for the greatest match
      versions = Object.keys(data.versions);
      version = semver.maxSatisfying(versions, versionMatch);
      if (version === null) {
        throw new Error(`No version available for ${moduleName} matching ${versionMatch}`);
      }

      processVersion(moduleName, version, data, specOnly, forceLicense);
    }
  });
}

function processModule(moduleName, versionMatch, isLocal, registryUrl, specOnly, forceLicense) {
  // if this is a local module, create a new tmp directory,
  // unpack the tarball and skip to makeSRPM
  if (isLocal) {
    tmp.dir({ unsafeCleanup: true }, (err, tmpPath) => {
      if (err) throw err;

      unpackTarball(moduleName, tmpPath)
        .on('finish', () => {
          makeSRPM(tmpPath,
            path.basename(moduleName),
            path.dirname(moduleName),
            path.join(tmpPath, 'package'),
            specOnly,
            forceLicense);
        });
    });
  } else {
    processModuleRegistry(moduleName, versionMatch, registryUrl, specOnly, forceLicense);
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
      default: 'https://registry.npmjs.org/',
      describe: 'Base URL of the npm registry to use',
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
    .strict();

  if (argv._.length === 0) {
    console.error('You must specify a module name');
    process.exit(1);
  }

  if (argv._.length > 1) {
    console.error('Only one module can be specified');
    process.exit(1);
  }

  try {
    let registryUrl = argv.registry;
    if (!registryUrl.endsWith('/')) {
      registryUrl += '/';
    }
    await processModule(argv._[0], argv.tag, argv.local, registryUrl, argv['spec-only'], argv['force-license']);
  } catch (e) {
    console.error(`Error creating SRPM: ${e}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
