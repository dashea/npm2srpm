#!/usr/bin/python3

import glob
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

from typing import Dict, List, Optional, Tuple  # pylint: disable=unused-import

from copr.v3 import Client  # type: ignore
import dnf                  # type: ignore
import rpm                  # type: ignore
# needs to be node-semver
import semver               # type: ignore

COPR_OWNER = 'dshea'
COPR_PROJECT = 'npmlib-packaging'
NPM2SRPM = 'npm2srpm'

# initialize the dnf sack from the system repos
# expire the metadata to ensure the copr stuff gets reloaded
subprocess.check_call(["dnf", "clean", "metadata"])
dnfBase = dnf.Base()
dnfBase.read_all_repos()
print("loading repo data...")
dnfBase.fill_sack(load_system_repo=False, load_available_repos=True)
print("done")

# initialize a copr client object
coprClient = Client.create_from_config_file()

# create a global dict for in-progress builds, so we don't have to keep hitting the repos
# keys are npm module names, values are a dictionary describing the versions in progress.
# the version dictionary is keyed by version number, and the values are an Event object,
# set to True when the build is complete
inProgress = {}     # type: Dict[str, Dict[str, threading.Event]]
inProgressLock = threading.Lock()

def getRPMHdr(path: str) -> rpm.hdr:
    ts = rpm.TransactionSet()
    fdno = os.open(path, os.O_RDONLY)
    hdr = ts.hdrFromFdno(fdno)
    os.close(fdno)

    return hdr

def getNV(hdr: rpm.hdr) -> Tuple[str, str]:
    # return the name with npmlib- stripped off
    return (hdr[rpm.RPMTAG_NAME].decode('ascii')[7:],
            hdr[rpm.RPMTAG_VERSION].decode('ascii'))

def processSRPM(path: str, tmpobj: Optional[tempfile.TemporaryDirectory]=None,
        pkgEvent: Optional[threading.Event]=None) -> threading.Thread:
    deplist = [] # type: List[threading.Thread]

    hdr = getRPMHdr(path)

    # If no event was passed in for this SRPM, create one and add it to the dict
    if pkgEvent is None:
        (moduleName, moduleVersion) = getNV(hdr)
        pkgEvent = threading.Event()
        with inProgressLock:    # pylint: disable=not-context-manager
            if moduleName not in inProgress:
                inProgress[moduleName] = {}
            inProgress[moduleName][moduleVersion] = pkgEvent

    # Convert the requirements from binary to str, and drop any that aren't npmlib(whatever)
    reqs = (s.decode('ascii') for s in hdr[rpm.RPMTAG_REQUIRES] if b'npmlib(' in s)

    # Look for deps not currently in the repo
    for req in reqs:
        matches = dnfBase.sack.query().filter(provides=req).run()
        if len(matches) > 0:
            continue

        # Look for the package in the pending versions
        moduleName = re.search(r'npmlib\(([^)]*)\)', req)[1]

        # Mangle the npm name into an rpm name
        rpmName = re.sub(r'/', '-', moduleName)
        rpmName = re.sub(r'@', '', rpmName)

        # convert the RPM boolean back to a semver-ish string by removing the npmlib(whatever) identifiers,
        # removing the spaces between operators and version numbers, replacing ' with ' with ' ', replacing
        # ' or ' with ' || ', and dropping all grouping parenthesis
        # if there is no operator in the expression, then there is no version
        if not re.search(r'[<>=]', req):
            reqSemver = None
        else:
            reqSemver = re.sub(r'npmlib\([^)]*\) ', '', req)
            reqSemver = re.sub(r'([<>=]) ', r'\1', reqSemver)
            reqSemver = re.sub(r' with ', ' ', reqSemver)
            reqSemver = re.sub(r' or ', ' || ', reqSemver)
            reqSemver = re.sub(r'[()]', '', reqSemver)

        event = None
        depEvent = None
        tempdir = None
        depRPM = ''

        # pylint doesn't understand locks, at least as of version 1.7.5
        with inProgressLock:    # pylint: disable=not-context-manager
            if rpmname in inProgress:
                for version in inProgress[rpmName].keys():
                    if semver.satisfies(version, reqSemver):
                        event = inProgress[rpmName][version]
                        break

            # if no event was found, create one add add it to the dict
            # while we still have the lock held
            if not event:
                # Make the rpm first to figure out the version
                tempdir = tempfile.TemporaryDirectory(prefix="npm2srpm.")
                args = [NPM2SRPM]
                if reqSemver:
                    args += ['-t', reqSemver]
                args += moduleName
                subprocess.check_call(args, cwd=tempdir.name)
                depRPM = glob.glob(os.path.join(tempdir.name, '*.rpm'))[0]
                depHdr = getRPMHdr(depRPM)
                (reqName, reqVer) = getNV(depHdr)

                depEvent = threading.Event()
                if reqName not in inProgress:
                    inProgress[reqName] = {}
                inProgress[reqName][reqVer] = depEvent

        if event:
            def _wait(event):
                event.wait()
                return

            waitThread = threading.Thread(target=_wait, args=(event,))
            waitThread.start()
            deplist.append(waitThread)
        else:
            deplist.append(processSRPM(depRPM, tempdir, depEvent))

    def _do_build(depThreads, tmpobj, eventObj):
        # wait for all of the dependent jobs to finish
        for dep in depThreads:
            dep.join()

        # start the build
        print("Starting build for %s" % path)
        build = coprClient.build_proxy.create_from_file(COPR_OWNER, COPR_PROJECT, path)

        # monitor the build
        while True:
            status = coprClient.build_proxy.get(build['id'])
            if status['state'] == 'succeeded':
                eventObj.set()
                print("Build finished for %s" % path)
                if tmpobj:
                    del tmpobj
                return
            if status['state'] == 'failed':
                print("BUILD FOR %s FAILED" % path)
                sys.exit(1)

            time.sleep(30)

    newThread = threading.Thread(target=_do_build, args=(deplist, tmpobj, pkgEvent))
    newThread.start()
    return newThread

# do the thing
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s SRPM [SRPM ...]" % sys.argv[0])
        sys.exit(1)

    for srpm in sys.argv[1:]:
        processSRPM(srpm).join()
