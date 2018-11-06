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

const child_process = require('child_process');
const csvParseSync = require('csv-parse/lib/sync');
const crypto = require('crypto');
const dateformat = require('dateformat');
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

var npmClient = new RegClient();
const npmClientConf = {timeout: 1000};

tmp.setGracefulCleanup();

// load the specfile template
const templateFile = 'specfile.hjs';
var templateData = fs.readFileSync(path.join(__dirname, templateFile), {encoding: 'utf-8'});
var template = handlebars.compile(templateData);

// load the license string CSV
const csvFile = 'spdx_to_fedora.csv';
var csvData = fs.readFileSync(path.join(__dirname, csvFile));
var licenseRecords = csvParseSync(csvData, {columns: true});

function unpackTarball(tarball, dest) {
  var gunzip = zlib.createGunzip();
  return fs.createReadStream(tarball).pipe(gunzip).pipe(tar.extract(dest));
}

function encodeModuleName(moduleName) {
  // handle npm's weird module name encoding: '/' is a legal
  // character, and it (and only it) should be URI-encoded (as %2F).
  return moduleName.replace(/\//g, '%2F');
}

function processModule(moduleName, versionMatch, isLocal, registryUrl, specOnly) {
  // if this is a local module, create a new tmp directory,
  // unpack the tarball and skip to makeSRPM
  if (isLocal) {
    tmp.dir({unsafeCleanup: true}, (err, tmpPath, cleanup) => {
      if (err) throw err;

      unpackTarball(moduleName, tmpPath)
        .on('finish', () => {
          makeSRPM(tmpPath, path.basename(moduleName), path.dirname(moduleName), path.join(tmpPath, 'package'), specOnly);
        });
    });
  } else {
    processModuleRegistry(moduleName, versionMatch, registryUrl, specOnly);
  }
}

function processModuleRegistry(moduleName, versionMatch, registryUrl, specOnly) {
  var uri = registryUrl + encodeModuleName(moduleName);

  npmClient.get(uri, npmClientConf, (error, data, raw, res) => {
    if (error) {
      throw error;
    }

    // find a matching version
    // start with the dist-tags
    if (versionMatch in data["dist-tags"]) {
      processVersion(moduleName, data["dist-tags"][versionMatch], registryUrl, specOnly);
    } else {
      // Otherwise, treat versionMatch as a semver expression and look
      // for the greatest match
      var versions = Object.keys(data.versions);
      var version = semver.maxSatisfying(versions, versionMatch);
      if (version === null) {
        throw "No version available for " + moduleName + " matching " + versionMatch;
      }

      processVersion(moduleName, version, registryUrl, specOnly);
    }
  });
}

function processVersion(moduleName, moduleVersion, registryUrl, specOnly) {
  // Grab and verify the dist tarball, unpack it
  tmp.dir({unsafeCleanup: true}, (err, tmpPath, cleanup) => {
    if (err) throw err;

    var uri = registryUrl + encodeModuleName(moduleName) + '/' + moduleVersion;

    npmClient.get(uri, npmClient, (err, data, raw, res) => {
      if (err) throw err;

      // parse the URL to get the filename
      var tarballName = new url.URL(data.dist.tarball).pathname.split('/').pop();

      var outputPath = path.join(tmpPath, tarballName);
      var outputStream = fs.createWriteStream(outputPath);

      // create a pass-through stream to calculate the SHA1 as we download
      var tee = new stream.PassThrough();
      var hash = crypto.createHash('sha1');
      tee
        .on('data', (chunk) => {
          hash.update(chunk);
          outputStream.write(chunk);
        });

      request(data.dist.tarball).pipe(tee)
        .on('finish', () => {
          var digest = hash.digest('hex');

          // check the hash
          if (digest !== data.dist.shasum) {
            throw "SHA1 digest for " + moduleName + "@" + moduleVersion + " does not match";
          }

          // unpack the tarball
          // tarballs from npm will unpack into a 'package' directory
          unpackTarball(outputPath, tmpPath)
            .on('finish', () => {
              makeSRPM(tmpPath, data.dist.tarball, path.dirname(outputPath), path.join(tmpPath, 'package'), specOnly);
            });
        });
    });
  });
}

function spdxToFedora(packageData) {
  var licenseString;
  if ("license" in packageData) {
    licenseString = packageData.license;
  } else if ("licenses" in packageData) {
    licenseString = packageData.licenses.map((license) => license.type).join(' or ');
  } else {
    throw "No license data found";
  }

  var fedoraLicense = spdxExpressionToFedora(spdxParse(spdxCorrect(licenseString)));
  if (fedoraLicense === null) {
    throw "No Fedora equivalent found for " + licenseString;
  }

  return fedoraLicense;
}

function spdxExpressionToFedora(expr) {
  if ('conjunction' in expr) {
    // try to find matches for each half
    var leftLicense = spdxExpressionToFedora(expr.left);
    var rightLicense = spdxExpressionToFedora(expr.right);

    if (expr.conjunction === "and") {
      // if either side is null, we cannot continue
      if (leftLicense === null || rightLicense === null) {
        return null;
      }

      return "(" + leftLicense + " and " + rightLicense + ")";
    } else {
      // if both sides are null, we cannot continue
      if (leftLicense === null && rightLicense === null) {
        return null;
      }

      // if one is null, just return the other
      if (leftLicense === null) {
        return rightLicense;
      } else if (rightLicense === null) {
        return leftLicense;
      } else {
        return "(" + leftLicense + " or " + rightLicense + ")";
      }
    }
  } else {
    // Find the SPDX license in the CSV data
    var spdxMatch = licenseRecords.filter((rec) => rec["SPDX License Identifier"] == expr.license);
    if (spdxMatch.length === 0) {
      // unsupported license
      return null;
    }
    if (spdxMatch.length > 1) {
      // data error
      throw "More than one license found for " + expr.license;
    }

    var fedoraName = spdxMatch[0]["Fedora Short Name"];
    if (!fedoraName) {
      return null;
    }

    return fedoraName;
  }
}

// convert one part of a semver range (i.e., >=1.2.3) to a RPM dep expression
function constraintToBuildReq(depName, constraint) {
  // If the contraint is "*", there is no version, so just return the
  // requirement name. If the contraint starts with '>' or '<'
  // (which includes '>=' and '<=', use it as-is. Otherwise, it's a single
  // version and we want a RPM requirement of '= <version>'.
  var reqName = 'npmlib(' + depName + ')';
  if (constraint == '*') {
    return reqName;
  } else if (constraint.startsWith('>') || constraint.startsWith('<')) {
    // add a space between the operator and the version number
    var constraintSpace = constraint
      .replace(/^>=/, '>= ')
      .replace(/^>([^=])/, '> $1')
      .replace(/^<=/, '<= ')
      .replace(/^<([^=])/, '< $1')
      .replace(/^=/, '= ');
    return reqName + ' ' + constraintSpace;
  } else {
    return reqName + ' = ' + constraint;
  }
}

function depsToBuildReqs(dep) {
  if (!dep) { return []; }

  return Object.entries(dep).map(([depName, depVersion]) => {
    // Normalize(ish) the version
    var versionRange = semver.validRange(depVersion);

    // If versionRange returned null, something went wrong
    if (versionRange === null) {
      throw "Invalid version range for " + depName + ": " + depVersion;
    }

    // result of validRange is now a DNF expression,
    // converted to a string as 'a b||c d', with spaces
    // being AND and || being OR. Split all of that back apart.
    var versionDNF = versionRange.split('||').map((s) => s.split(' '));

    // convert each of the version units to an RPM expression
    var buildReqDNF = versionDNF.map((andExp) => 
      andExp.map((exp) => constraintToBuildReq(depName, exp)
      )
    );

    // for each of the AND clauses (the inner expressions), we want to
    // convert 'a AND b' into 'a with b'.
    // Each of the OR expressions just becomes 'a or b'.
    // wrap the whole thing in parenthesis to tell RPM it's a boolean dep
    var rpmExpression = "(" +
      buildReqDNF.map((andExp) => "(" + andExp.join(' with ') + ")")
        .join(' or ') +
      ")";

    // wrap the whole thing in an object for the template
    return {buildRequiresExp: rpmExpression};
  });
}

function mapBin(bin) {
  if (!bin) {
    return [];
  } else {
    return Object.entries(bin).map(([binPath, modulePath]) => {
      return {modulePath: path.normalize(modulePath), binPath: binPath};
    });
  }
}

// split up man pages by section
function mapMan(tmpPath, man) {

  // start with an object indexed by section number, each section number
  // containing an array of man pages in that section
  // e.g., {"1": ['./man/cool-program.1', './man/lame-program.1.gz'], "5": ['./man/cool-program.conf.5']}
  var manSections = {};
  if (man) {
    man.forEach((s) => {
      var sectionMatch = s.match(/\.([0-9]+)(\.gz)?$/);
      if (sectionMatch === null) {
        throw "Invalid man page name: " + s;
      }

      var section = sectionMatch[1];
      if (!(section in manSections)) {
        manSections[section] = new Array();
      }
      manSections[section].push(s);
    });
  }

  // convert that into something more usable by the template
  // [ {manSection: "1", manPages: [{modulePath: './man/cool-program.1', manPath: 'cool-program.1', compressed: false},
  //                                {modulePath: './man/lame-program.1', manPath: 'lame-program.1.gz', compressed: true}] },
  //   {manSection: "5", manPages: [{modulePath: './man/cool-program.conf.5', manPath: 'cool-program.conf.5', compressed: false}]}]
  return Object.entries(manSections).map(([section, files]) => {
    return {manSection: section,
      manPages: files.map((f) => { 
        // if the man object was generated from directories.man, it's full of absolute
        // paths. We need those to be relative to the package directory.
        var modulePath = path.relative(path.join(tmpPath, 'package'), f);
        return {modulePath: modulePath, manPath: path.basename(f), compressed: f.endsWith('.gz')}; 
      })};
  });
}

function makeSRPM(tmpPath, sourceUrl, sourceDir, modulePath, specOnly) {
  // Read the package.json file
  // use read-package-json to normalize the data
  readPackageJSON(path.join(modulePath, 'package.json'), (err, packageData) => {
    if (err) throw err;
    var moduleName = packageData.name.replace(/\//g, '-');
    var packageName = 'npmlib-' + moduleName;

    // Read the package directory for the top-level filenames, split them
    // up by license, doc, other
    fs.readdir(modulePath, (err, packageList) => {
      if (err) throw err;

      var docList = [];
      var licenseList = [];
      var fileList = [];

      packageList.forEach((fileName) => {
        // ignore node_modules if present
        if (fileName == "node_modules") {
          return;
        } else if (fileName.match(/\.txt$|\.md$|authors|readme|contributing|docs/i)) {
          docList.push({docName: fileName});
        } else if (fileName.match(/license|copying/i)) {
          licenseList.push({licenseName: fileName});
        } else {
          fileList.push({fileName: fileName});
        }
      });

      // if no homepage is present in package.json, try repo
      var packageUrl;
      if (packageData.homepage) {
        packageUrl = packageData.homepage;
      } else if (packageData.repository) {
        packageUrl = packageData.repository.url;
      } else {
        packageUrl = null;
      }

      var manList = mapMan(tmpPath, packageData.man);
      // whether any man pages included in npm-library are compressed
      var compressedManPages = manList.some((section) => section.manPages.some((page) => page.compressed));

      // construct the data for the template
      var specData = {
        name: moduleName,
        version: packageData.version,
        summary: packageData.description.split('\n')[0],
        description: packageData.description,
        license: spdxToFedora(packageData),
        url: packageUrl,
        sourceUrl: sourceUrl,
        buildRequires: depsToBuildReqs(packageData.dependencies),
        description: packageData.description,
        binList: mapBin(packageData.bin),
        cldate: dateformat(Date(), 'ddd mmm d yyyy'),
        fileList: fileList,
        docList: docList,
        licenseList: licenseList,
        manList: mapMan(tmpPath, packageData.man),
        compressedManPages: compressedManPages
      };

      var specFileData = template(specData);
      var specFilePath = 'npmlib-' + moduleName + '.spec';

      // if only the spec file is requested, just write it to the current directory
      if (specOnly) {
        fs.writeFile(specFilePath, specFileData, {encoding: 'utf-8'}, (err) => {
          if (err) throw err;
          console.log('Wrote: ' + specFilePath);
        });
      } else {
        // write the spec file to the tmp directory
        fs.writeFile(path.join(tmpPath, specFilePath), specFileData, {encoding: 'utf-8'}, (err) => {
            if (err) throw err;

            // create an SRPM
            child_process.execFile('rpmbuild',
              ['-bs',
                '-D', '_srcrpmdir .',
                '-D', '_sourcedir ' + sourceDir,
                '-D', '_specdir ' + tmpPath,
                path.join(tmpPath, specFilePath)
              ], (err, stdout, stderr) => {
                if (err) {
                  console.error(stderr);
                  throw err;
                }

                process.stdout.write(stdout);
                process.stderr.write(stderr);
              });
          });
      }
    });
  });
}

async function main() {
  const argv = yargs
    .usage('$0 [options] MODULE')
    .option('tag', {
      alias: 't',
      default: 'latest',
      describe: 'Install the given tag or version',
      type: 'string'
    })
    .option('local', {
      type: 'boolean',
      default: false,
      describe: 'Use a local module tarball instead of a npm registry'
    })
    .option('registry', {
      type: 'string',
      default: 'https://registry.npmjs.org/',
      describe: 'Base URL of the npm registry to use'
    })
    .option('spec-only', {
      type: 'boolean',
      default: false,
      describe: 'Output only a .spec file instead of a SRPM'
    })
    .strict()
    .argv;

  if (argv._.length === 0) {
    console.error("You must specify a module name");
    process.exit(1);
  }

  if (argv._.length > 1) {
    console.error("Only one module can be specified");
    process.exit(1);
  }

  try {
    var registryUrl = argv.registry;
    if (!registryUrl.endsWith('/')) {
      registryUrl += '/';
    }
    await processModule(argv._[0], argv.tag, argv.local, registryUrl, argv['spec-only']);
  } catch (e) {
    console.error("Error creating SRPM: " + e);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
