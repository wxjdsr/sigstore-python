# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import shutil
import sys
from importlib import resources
from pathlib import Path
from typing import Dict, Optional

from tuf.api.metadata import Metadata, TargetFile, Targets, Timestamp
from tuf.ngclient import Updater

from sigstore._store import Store, SIGSTORE_TARGETS


PUBLIC_GOOD_URL = "https://storage.googleapis.com/sigstore-tuf-root/"
EXPECTED_ROOT_DIGEST = (  # corresponds to public good 4.root.json
    "8e34a5c236300b92d0833b205f814d4d7206707fc870d3ff6dcf49f10e56ca0a"
)


# TODO: tests!
# * _prepare_local_cache() against a simple adversary
# * _should_update() against a simple adversary – what if
# * update() results in new files (i.e. local copies of TUF metadata)
class TrustUpdater:
    def __init__(self, tuf_dir: Optional[str] = None) -> None:
        # [WIP] debugging
        # import pdb; pdb.set_trace()
        # [TODO] handle with "FileNotFoundError"

        #? [Question] Optional directory sounds good, but how should we use it?
        if tuf_dir:
            _tuf_dir = Path(tuf_dir)
        else:
            _tuf_dir = Path.home() / ".sigstore" / "root"
        # TODO: this should be a param in order to support private and staging
        # instances of Sigstore
        self._repo_url = PUBLIC_GOOD_URL
        self._prepare_local_cache(_tuf_dir)

    def _prepare_local_cache(self, tuf_dir: Path) -> None:
        """
        Create and populate the local directories used by the TUF client
        """
        self._metadata_dir = tuf_dir / "metadata"
        self._targets_dir = tuf_dir / "targets"
        tuf_root = self._metadata_dir / "root.json"
        if not tuf_root.exists():
            tuf_dir.mkdir(mode=0o0700, parents=True, exist_ok=True)
            self._metadata_dir.mkdir(mode=0o0700, parents=True, exist_ok=True)
            self._targets_dir.mkdir(mode=0o0700, parents=True, exist_ok=True)

            # Copy the trusted root and existing targets from the store
            # TODO: we need to be able to take a root.json that wasn't bundled
            #  with the implementation, i.e. for private sigstore deployments
            
            with resources.path("sigstore._store", "root.json") as res:
                shutil.copy2(res, self._metadata_dir)
            for target in SIGSTORE_TARGETS:
                with resources.path("sigstore._store", target) as res:
                    shutil.copy2(res, self._targets_dir)
            # TODO: ensure the directory has appropriate file permissions?

        # Ensure the bundled copy of the root json is not tampered with
        # NOTE: this check requires us to update EXPECTED_ROOT_DIGEST each
        # time we bundle a newer root.json
        # TODO: what if we're not using the public good instance? A user must be
        # able to supply their own root.json
        bootstrap_root = Store._read_binary("root.json")
        bootstrap_root_digest = hashlib.sha256(bootstrap_root).hexdigest()
        if not bootstrap_root_digest == EXPECTED_ROOT_DIGEST:
            print(
                "Trusted root metadata does not match expected file digest!",
                file=sys.stderr
            )
            sys.exit(1)

    def _should_update(self) -> bool:
        """
        Should we reach out over the network to update TUF metadata?
        """
        # if we don't already have a downloaded timestamp metadata, we need
        # to update
        timestamp_path = self._metadata_dir / "timestamp.json"
        if not timestamp_path.exists():
            return True
        # if timestamp metadata has expired, we need to update
        timestamp = Metadata[Timestamp].from_file(str(timestamp_path))
        if timestamp.signed.is_expired():
            return True

        return False

    def update(self) -> None:
        """
        Update the TUF metadata and fetch any updated targets. Steps 2, 3, 4
        of the design (step 1 is handled by our constructor)
        https://docs.google.com/document/d/1QWBvpwYxOy9njAmd8vpizNQpPti9rd5ugVhji0r3T4c/
        """
        if not self._should_update():
            return

        updater = Updater(
            metadata_dir=str(self._metadata_dir),
            metadata_base_url=f"{self._repo_url}",
            target_base_url=f"{self._repo_url}targets/",
            target_dir=str(self._targets_dir),
        )

        # TODO: TAP 4: multi-repository consensus on entrusted targets
        # https://github.com/theupdateframework/taps/blob/master/tap4.md
        
        # Fetch the latest version of all of the Sigstore certificates
        # FIXME: handle `refresh()` failure.
        updater.refresh()
        
        # Once refresh is done, we have the latest top-level metadata
        # Now, get all targets delegated to by Targets role and all top-level
        # delegations.
        # TODO: once consistent snapshot is enabled we'll need a way to find
        # the most recent VER.targets.json – for now it's a little easier.
        # This would likely be cleaner as some API in python-tuf, we could
        # access this via TrustedMetadataSet, but that's private API.
        # Ultimately, clients parsing raw metadata is a code smell.
        # The required API is: get all targets, including delegations,
        # optionally filtered by target consumption, that is the custom
        # metadata sigstore uses – status, uri, id:
        # "custom":{
        #   "sigstore":{
        #     "status":"Active",
        #     "uri":"https://rekor.sigstore.dev",
        #     "id": "3904496407287907110"
        #   }
        # The design calls for us to be able to filter by PATHPATTERN, because
        # USAGE is indicated by delegation path: $USAGE/**/$TARGET, thus we
        # should be able to filter for all targets that match a PATHPATTERN.
        targets_path = self._metadata_dir / "targets.json"
        targets_md = Metadata[Targets].from_file(str(targets_path))

        # WIP locally scoped function as we'll repeat this logic for
        # top-level Targets and all delegated Targets roles
        def _fetch_all_targets(targets: Dict[str, TargetFile]) -> None:

            for target in targets:
                target_info = updater.get_targetinfo(target)
                if not target_info:
                    print(
                        f"Failed to find update information about {target}", sys.stderr
                    )
                    sys.exit(1)
                cached_target = updater.find_cached_target(target_info)
                if not cached_target:
                    updater.download_target(target_info)

        # Fetch all targets listed in the top-level Targets metadata
        import pdb; pdb.set_trace()
        _fetch_all_targets(targets_md.signed.targets)
        # I now want to walk delegations and fetch their targets, however
        # python-tuf API is designed to enable the TUF client workflow where
        # it's expected that you know the name of the target you're looking for
        # and only download new delegated Targets metadata when the delegation
        # pattern matches. For us, we want to download the delegated Targets
        # metadata, extract information about the targets, then fetch them.
        # This is an impedence mismatch which may require new python-tuf API.

        # TODO: split into a function and enable callers to fetch by usage type,
        # that way a client that only interacts with one usage type's material
        # need not download all targets and should therefore be more efficient.
        for usage in ["fulcio", "rekor", "ct_log", "custom_key_material"]:
            # TODO: verify this PATHPATTERN is correct per glob (7) semantics:
            # https://man7.org/linux/man-pages/man7/glob.7.html
            usage_pattern = f"{usage}/**/*"
            # [TODO] AttributeError: 'Metadata' object has no attribute 'delegations'
            for (role, _) in targets_md.delegations.get_roles_for_target(usage_pattern):
                # load the metadata
                # "fortunately" we're not yet using consistent snapshots, so we do not
                # need to first look up role in the _latest_ snapshot...
                # TODO: this will be awful with consistent snapshots enabled
                role_path = self._metadata_dir / f"{role}.json"
                role_md = Metadata[Targets].from_file(str(role_path))
                # get all targets listed by the role
                _fetch_all_targets(role_md.signed.targets.targets)

    @classmethod
    def is_created(tuf_dir: Optional[str] = None) -> bool:
        """
        Has the TUF update cycle triggered by `update()` has been run at least
        once? If it has, we would expect the timestamp metadata to have been
        retrieved and stored in the cache.
        """
        if tuf_dir:
            _tuf_dir = Path(tuf_dir)
        else:
            _tuf_dir = Path.home() / ".sigstore" / "root"
        timestamp_path = _tuf_dir / "metadata" / "timestamp.json"
        return timestamp_path.exists()
