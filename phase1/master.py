# -*- python -*-
# ex: set filetype=python:

from buildbot.plugins import changes, worker, schedulers
from buildbot.plugins import util
from buildbot.process import properties
from buildbot.process.factory import BuildFactory
from buildbot.process.properties import Interpolate
from buildbot.steps.master import MasterShellCommand
from buildbot.steps.shell import SetPropertyFromCommand
from buildbot.steps.shell import ShellCommand
from buildbot.steps.source.git import Git
from buildbot.steps.transfer import FileDownload
from buildbot.steps.transfer import FileUpload
from buildbot.steps.transfer import StringDownload
from configparser import ConfigParser
from datetime import timedelta
from os import getenv
from pathlib import Path
import base64
import os
import re
import subprocess

# Load .ini config file so it is easier to configure the buildbot
ini = ConfigParser()
ini.read(getenv("BUILDMASTER_CONFIG", "./config.ini"))
c = BuildmasterConfig = {}

c["buildbotNetUsageData"] = "full"
c["configurators"] = [
    util.JanitorConfigurator(logHorizon=timedelta(weeks=4), hour=12, dayOfWeek=6)
]
c["services"] = []
c["title"] = ini.get("general", "title")
c["titleURL"] = ini.get("general", "title_url")
c["buildbotURL"] = ini.get("phase1", "buildbot_url")
c["www"] = dict(
    port=8010, plugins=dict(waterfall_view={}, console_view={}, grid_view={})
)

authz = util.Authz(
    allowRules=[util.AnyControlEndpointMatcher(role="admins")],
    roleMatchers=[util.RolesFromUsername(roles=["admins"], usernames=["status"])],
)
auth = util.UserPasswordAuth(
    {ini.get("phase1", "status_user"): ini.get("phase1", "status_password")}
)
c["www"]["auth"] = auth
c["www"]["authz"] = authz
c["db"] = {"db_url": "sqlite:///state.sqlite"}

c["workers"] = []
NetLocks = dict()

for section in ini.sections():
    if section.startswith("worker "):
        name = ini.get(section, "name", fallback=None)
        password = ini.get(section, "password", fallback=None)

        if not (name and password):
            # Every worker requires a name and a password at least
            continue
        if not ini.getint(section, "phase", fallback=1) == 1:
            # Only use worker with phase undefined or phase 1
            continue

        p = {
            "dl_lock": ini.get(section, "dl_lock", fallback=None),
            "ul_lock": ini.get(section, "ul_lock", fallback=None),
            "do_cleanup": ini.getboolean(section, "cleanup", fallback=False),
            "max_builds": ini.getint(section, "builds", fallback=1),
            "shared_wd": ini.getboolean(section, "shared_wd", fallback=False),
        }

        # Parrallel builds can where the working directory
        if p["max_builds"] == 1:
            p["shared_wd"] = True

        if p["dl_lock"] and p["dl_lock"] not in NetLocks:
            NetLocks[p["dl_lock"]] = util.MasterLock(p["dl_lock"])

        if p["ul_lock"] and p["ul_lock"] not in NetLocks:
            NetLocks[p["ul_lock"]] = util.MasterLock(p["ul_lock"])

        c["workers"].append(
            worker.Worker(name, password, max_builds=p["max_builds"], properties=p)
        )

c["protocols"] = {"pb": {"port": ini.getint("phase1", "port", fallback=9989)}}
c["collapseRequests"] = True

work_dir = os.path.abspath(ini.get("general", "workdir") or ".")
workdir = Path(ini.get("general", "workdir") or ".").absolute()
scripts_dir = os.path.abspath("../scripts")

cc_version = ini.get("phase1", "cc_version")
if cc_version:
    cc_version = cc_version.split()
    if len(cc_version) == 1:
        cc_version = ["eq", cc_version[0]]

tree_expire = ini.getint("phase1", "expire", fallback=0)
other_builds = ini.getint("phase1", "other_builds", fallback=0)
git_ssh = ini.getboolean("general", "git_ssh", fallback=False)
git_ssh_key = ini.get("general", "git_ssh_key", fallback=None)
config_seed = ini.get("phase1", "config_seed", fallback="")
enable_kmod_archive = ini.getboolean("phase1", "enable_kmod_archive", fallback=True)

repo_url = ini.get("repo", "url")
repo_branch = ini.get("repo", "branch", fallback="master")

rsync_bin_url = ini.get("rsync", "binary_url")
rsync_bin_key = ini.get("rsync", "binary_password")
rsync_bin_defopts = ["-v", "-4", "--timeout=120"]

if rsync_bin_url.find("::") > 0 or rsync_bin_url.find("rsync://") == 0:
    rsync_bin_defopts += ["--contimeout=20"]

rsync_src_url = None
rsync_src_key = None
rsync_src_defopts = ["-v", "-4", "--timeout=120"]

rsync_src_url = ini.get("rsync", "source_url")
rsync_src_key = ini.get("rsync", "source_password")
rsync_src_defopts = ["-v", "-4", "--timeout=120"]
if rsync_src_url:
    if rsync_src_url.find("::") > 0 or rsync_src_url.find("rsync://") == 0:
        rsync_src_defopts += ["--contimeout=20"]

usign_key = ini.get("usign", "key", fallback=None)
usign_comment = ini.get(
    "usign",
    "comment",
    fallback="untrusted comment: " + repo_branch.replace("-", " ").title() + " key",
)


if ini.has_section("external_targets"):
    external_targets = ini.options("external_targets")
else:
    external_targets = {}

external_targets_only = ini.getboolean(
    "phase1", "external_targets_only", fallback=False
)

source_git = workdir / "source.git"
source_git.parent.mkdir(parents=True, exist_ok=True)

if not source_git.is_dir():
    subprocess.run(
        ["git", "clone", "--depth=1", "--branch=" + repo_branch, repo_url, source_git]
    )
else:
    subprocess.call(["git", "pull"], cwd=source_git)

if external_targets:
    feeds_conf = (source_git / "feeds.conf.default").read_text()

    for external_target in external_targets:
        feeds_conf += "{1} {0} {2}\n".format(
            external_target, *ini.get("external_targets", external_target).split(",")
        )

    (source_git / "feeds.conf").write_text(feeds_conf)

    subprocess.call(
        ["scripts/feeds", "update", " ".join(external_targets)], cwd=source_git
    )
    subprocess.call(
        ["scripts/feeds", "install", " ".join(external_targets)], cwd=source_git
    )

targets_available = list(
    map(
        lambda t: t.split()[0],
        subprocess.run(
            [scripts_dir + "/dumpinfo.pl", "targets"],
            cwd=source_git,
            capture_output=True,
            text=True,
        ).stdout.splitlines(),
    )
)

targets = []

if not ini.has_section("active_profiles"):
    if not external_targets_only:
        targets.extend(targets_available)
    else:
        targets.extend(
            list(
                filter(
                    lambda t: t.startswith(tuple(external_targets)), targets_available
                )
            )
        )
else:
    active_profiles = ini.options("active_profiles")
    for active_profile in active_profiles:
        targets.append(
            "{}/{}".format(ini.get("active_profiles", active_profile), active_profile)
        )


c["change_source"] = []
c["change_source"].append(
    changes.GitPoller(
        repo_url,
        workdir=work_dir + "/work.git",
        branches=[repo_branch],
        pollinterval=300,
    )
)

c["schedulers"] = []
c["schedulers"].append(
    schedulers.SingleBranchScheduler(
        name="all",
        change_filter=util.ChangeFilter(branch=repo_branch),
        treeStableTimer=60,
        builderNames=targets,
    )
)
c["schedulers"].append(schedulers.ForceScheduler(name="force", builderNames=targets))
c["services"] = []
c["title"] = ini.get("general", "title")
c["titleURL"] = ini.get("general", "title_url")
c["buildbotURL"] = ini.get("phase1", "buildbot_url")
c["www"] = dict(
    port=8010, plugins=dict(waterfall_view={}, console_view={}, grid_view={})
)

authz = util.Authz(
    allowRules=[util.AnyControlEndpointMatcher(role="admins")],
    roleMatchers=[util.RolesFromUsername(roles=["admins"], usernames=["status"])],
)
auth = util.UserPasswordAuth(
    {ini.get("phase1", "status_user"): ini.get("phase1", "status_password")}
)
c["www"]["auth"] = auth
c["www"]["authz"] = authz
c["db"] = {"db_url": "sqlite:///state.sqlite"}

CleanTargetMap = [
    ["tools", "tools/clean"],
    ["chain", "toolchain/clean"],
    ["linux", "target/linux/clean"],
    ["dir", "dirclean"],
    ["dist", "distclean"],
]


def IsMakeCleanRequested(pattern):
    def CheckCleanProperty(step):
        val = step.getProperty("clean")
        if val and re.match(pattern, val):
            return True
        else:
            return False

    return CheckCleanProperty


def IsSharedWorkdir(step):
    return bool(step.getProperty("shared_wd"))


def IsCleanupRequested(step):
    if IsSharedWorkdir(step):
        return False
    do_cleanup = step.getProperty("do_cleanup")
    if do_cleanup:
        return True
    else:
        return False


def IsExpireRequested(step):
    if IsSharedWorkdir(step):
        return False
    else:
        return not IsCleanupRequested(step)


def IsGitFreshRequested(step):
    do_cleanup = step.getProperty("do_cleanup")
    if do_cleanup:
        return True
    else:
        return False


def IsGitCleanRequested(step):
    return not IsGitFreshRequested(step)


def IsTaggingRequested(step):
    val = step.getProperty("tag")
    if val and re.match(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?$", val):
        return True
    else:
        return False


def IsNoTaggingRequested(step):
    return not IsTaggingRequested(step)


def IsNoMasterBuild(step):
    return repo_branch != "master"


def GetBaseVersion():
    if re.match(r"^[^-]+-[0-9]+\.[0-9]+$", repo_branch):
        return repo_branch.split("-")[1]
    else:
        return "master"


@properties.renderer
def GetVersionPrefix(props):
    basever = GetBaseVersion()
    if props.hasProperty("tag") and re.match(
        r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?$", props["tag"]
    ):
        return "%s/" % props["tag"]
    elif basever != "master":
        return "%s-SNAPSHOT/" % basever
    else:
        return ""


@properties.renderer
def get_num_jobs(props: dict) -> str:
    """Returns number of concurrent jobs

    Args:
        props (dict): Should contain max_builds and nproc

    Returns:
        str: Number of concurrent jobs
    """
    if props.hasProperty("max_builds") and props.hasProperty("nproc"):
        return str(int(int(props["nproc"]) / (props["max_builds"] + other_builds)))
    else:
        return "1"


@properties.renderer
def GetCC(props):
    if props.hasProperty("cc_command"):
        return props["cc_command"]
    else:
        return "gcc"


@properties.renderer
def GetCXX(props):
    if props.hasProperty("cxx_command"):
        return props["cxx_command"]
    else:
        return "g++"


@properties.renderer
def GetCwd(props):
    if props.hasProperty("builddir"):
        return props["builddir"]
    elif props.hasProperty("workdir"):
        return props["workdir"]
    else:
        return "/"


@properties.renderer
def GetCCache(props):
    if props.hasProperty("ccache_command") and "ccache" in props["ccache_command"]:
        return props["ccache_command"]
    else:
        return ""


def GetNextBuild(builder, requests):
    for r in requests:
        if r.properties and r.properties.hasProperty("tag"):
            return r
    return requests[0]


def MakeEnv(overrides=None, tryccache=False):
    env = {
        "CCC": Interpolate("%(kw:cc)s", cc=GetCC),
        "CCXX": Interpolate("%(kw:cxx)s", cxx=GetCXX),
    }
    if tryccache:
        env["CC"] = Interpolate("%(kw:cwd)s/ccache_cc.sh", cwd=GetCwd)
        env["CXX"] = Interpolate("%(kw:cwd)s/ccache_cxx.sh", cwd=GetCwd)
        env["CCACHE"] = Interpolate("%(kw:ccache)s", ccache=GetCCache)
    else:
        env["CC"] = env["CCC"]
        env["CXX"] = env["CCXX"]
        env["CCACHE"] = ""
    if overrides:
        env.update(overrides)
    return env


@properties.renderer
def NetLockDl(props):
    lock = None
    if props.hasProperty("dl_lock"):
        lock = NetLocks[props["dl_lock"]]
    if lock:
        return [lock.access("exclusive")]
    else:
        return []


@properties.renderer
def NetLockUl(props):
    lock = None
    if props.hasProperty("ul_lock"):
        lock = NetLocks[props["ul_lock"]]
    if lock:
        return [lock.access("exclusive")]
    else:
        return []


def usign_sec_2_pub(seckey: str, comment: str = "untrusted comment: secret key") -> str:
    """Convert usign private key to public key

    Args:
        seckey(str): The secret usign key
        comment(str): The comment above the actual key

    Returns:
        str: The public key
    """
    seckey = base64.b64decode(seckey)

    return "{}\n{}".format(
        re.sub(r"\bsecret key$", "public key", comment),
        base64.b64encode(seckey[0:2] + seckey[32:40] + seckey[72:]),
    )


c["builders"] = []

dlLock = util.WorkerLock("worker_dl")

checkBuiltin = re.sub(
    "[\t\n ]+",
    " ",
    """
	checkBuiltin() {
		local symbol op path file;
		for file in $CHANGED_FILES; do
			case "$file" in
				package/*/*) : ;;
				*) return 0 ;;
			esac;
		done;
		while read symbol op path; do
			case "$symbol" in package-*)
				symbol="${symbol##*(}";
				symbol="${symbol%)}";
				for file in $CHANGED_FILES; do
					case "$file" in "package/$path/"*)
						grep -qsx "$symbol=y" .config && return 0
					;; esac;
				done;
			esac;
		done < tmp/.packagedeps;
		return 1;
	}
""",
).strip()


class IfBuiltinShellCommand(ShellCommand):
    def _quote(self, str):
        if re.search("[^a-zA-Z0-9/_.-]", str):
            return "'%s'" % (re.sub("'", "'\"'\"'", str))
        return str

    def setCommand(self, command):
        if not isinstance(command, (str, unicode)):
            command = " ".join(map(self._quote, command))
        self.command = [
            "/bin/sh",
            "-c",
            "%s; if checkBuiltin; then %s; else exit 0; fi" % (checkBuiltin, command),
        ]

    def setupEnvironment(self, cmd):
        workerEnv = self.workerEnvironment
        if not workerEnv:
            workerEnv = {}
        changedFiles = {}
        for request in self.build.requests:
            for source in request.sources:
                for change in source.changes:
                    for file in change.files:
                        changedFiles[file] = True
        fullWorkerEnv = workerEnv.copy()
        fullWorkerEnv["CHANGED_FILES"] = " ".join(changedFiles.keys())
        cmd.args["env"] = fullWorkerEnv


workerNames = []

for worker in c["workers"]:
    workerNames.append(worker.workername)

for target in targets:
    ts = target.split("/")

    factory = BuildFactory()

    # setup shared work directory if required
    factory.addStep(
        ShellCommand(
            name="sharedwd",
            description="Setting up shared work directory",
            command='test -L "$PWD" || (mkdir -p ../shared-workdir && rm -rf "$PWD" && ln -s shared-workdir "$PWD")',
            workdir=".",
            haltOnFailure=True,
            doStepIf=IsSharedWorkdir,
        )
    )

    # find number of cores
    factory.addStep(
        SetPropertyFromCommand(
            name="nproc",
            property="nproc",
            description="Finding number of CPUs",
            command=["nproc"],
        )
    )

    # find gcc and g++ compilers
    factory.addStep(
        FileDownload(
            name="dlfindbinpl",
            mastersrc=scripts_dir + "/findbin.pl",
            workerdest="../findbin.pl",
            mode=0o755,
        )
    )

    factory.addStep(
        SetPropertyFromCommand(
            name="gcc",
            property="cc_command",
            description="Finding gcc command",
            command=[
                "../findbin.pl",
                "gcc",
                cc_version[0] if cc_version else "",
                cc_version[1] if cc_version else "",
            ],
            haltOnFailure=True,
        )
    )

    factory.addStep(
        SetPropertyFromCommand(
            name="g++",
            property="cxx_command",
            description="Finding g++ command",
            command=[
                "../findbin.pl",
                "g++",
                cc_version[0] if cc_version else "",
                cc_version[1] if cc_version else "",
            ],
            haltOnFailure=True,
        )
    )

    # see if ccache is available
    factory.addStep(
        SetPropertyFromCommand(
            property="ccache_command",
            command=["which", "ccache"],
            description="Testing for ccache command",
            haltOnFailure=False,
            flunkOnFailure=False,
            warnOnFailure=False,
        )
    )

    # expire tree if needed
    if tree_expire > 0:
        factory.addStep(
            FileDownload(
                name="dlexpiresh",
                doStepIf=IsExpireRequested,
                mastersrc=scripts_dir + "/expire.sh",
                workerdest="../expire.sh",
                mode=0o755,
            )
        )

        factory.addStep(
            ShellCommand(
                name="expire",
                description="Checking for build tree expiry",
                command=["./expire.sh", str(tree_expire)],
                workdir=".",
                haltOnFailure=True,
                doStepIf=IsExpireRequested,
                timeout=2400,
            )
        )

    # cleanup.sh if needed
    factory.addStep(
        FileDownload(
            name="dlcleanupsh",
            mastersrc=scripts_dir + "/cleanup.sh",
            workerdest="../cleanup.sh",
            mode=0o755,
            doStepIf=IsCleanupRequested,
        )
    )

    factory.addStep(
        ShellCommand(
            name="cleanold",
            description="Cleaning previous builds",
            command=[
                "./cleanup.sh",
                c["buildbotURL"],
                Interpolate("%(prop:workername)s"),
                Interpolate("%(prop:buildername)s"),
                "full",
            ],
            workdir=".",
            haltOnFailure=True,
            doStepIf=IsCleanupRequested,
            timeout=2400,
        )
    )

    factory.addStep(
        ShellCommand(
            name="cleanup",
            description="Cleaning work area",
            command=[
                "./cleanup.sh",
                c["buildbotURL"],
                Interpolate("%(prop:workername)s"),
                Interpolate("%(prop:buildername)s"),
                "single",
            ],
            workdir=".",
            haltOnFailure=True,
            doStepIf=IsCleanupRequested,
            timeout=2400,
        )
    )

    # user-requested clean targets
    for tuple in CleanTargetMap:
        factory.addStep(
            ShellCommand(
                name=tuple[1],
                description='User-requested "make %s"' % tuple[1],
                command=["make", tuple[1], "V=s"],
                env=MakeEnv(),
                doStepIf=IsMakeCleanRequested(tuple[0]),
            )
        )

    # Workaround bug when switching from a checked out tag back to a branch
    # Ref: http://lists.infradead.org/pipermail/openwrt-devel/2019-June/017809.html
    factory.addStep(
        ShellCommand(
            name="gitcheckout",
            description="Ensure that Git HEAD is sane",
            command="if [ -d .git ]; then git checkout -f %s; git branch --set-upstream-to origin/%s; else exit 0; fi"
            % (repo_branch, repo_branch),
            haltOnFailure=True,
        )
    )

    # check out the source
    # Git() runs:
    # if repo doesn't exist: 'git clone repourl'
    # method 'clean' runs 'git clean -d -f', method fresh runs 'git clean -d -f x'. Only works with mode='full'
    # 'git fetch -t repourl branch; git reset --hard revision'
    # Git() parameters can't take a renderer until buildbot 0.8.10, so we have to split the fresh and clean cases
    # if buildbot is updated, one can use: method = Interpolate('%(prop:do_cleanup:#?|fresh|clean)s')
    factory.addStep(
        Git(
            name="gitclean",
            repourl=repo_url,
            branch=repo_branch,
            mode="full",
            method="clean",
            haltOnFailure=True,
            doStepIf=IsGitCleanRequested,
        )
    )

    factory.addStep(
        Git(
            name="gitfresh",
            repourl=repo_url,
            branch=repo_branch,
            mode="full",
            method="fresh",
            haltOnFailure=True,
            doStepIf=IsGitFreshRequested,
        )
    )

    # update remote refs
    factory.addStep(
        ShellCommand(
            name="fetchrefs",
            description="Fetching Git remote refs",
            command=[
                "git",
                "fetch",
                "origin",
                "+refs/heads/%s:refs/remotes/origin/%s" % (repo_branch, repo_branch),
            ],
            haltOnFailure=True,
        )
    )

    # switch to tag
    factory.addStep(
        ShellCommand(
            name="switchtag",
            description="Checking out Git tag",
            command=["git", "checkout", Interpolate("tags/v%(prop:tag:-)s")],
            haltOnFailure=True,
            doStepIf=IsTaggingRequested,
        )
    )

    # Verify that Git HEAD points to a tag or branch
    # Ref: http://lists.infradead.org/pipermail/openwrt-devel/2019-June/017809.html
    factory.addStep(
        ShellCommand(
            name="gitverify",
            description="Ensure that Git HEAD is pointing to a branch or tag",
            command='git rev-parse --abbrev-ref HEAD | grep -vxqF HEAD || git show-ref --tags --dereference 2>/dev/null | sed -ne "/^$(git rev-parse HEAD) / { s|^.*/||; s|\\^.*||; p }" | grep -qE "^v[0-9][0-9]\\."',
            haltOnFailure=True,
        )
    )

    factory.addStep(
        ShellCommand(
            name="rmtmp", description="Remove tmp folder", command=["rm", "-rf", "tmp/"]
        )
    )

    # feed
    # 	factory.addStep(ShellCommand(
    # 		name = "feedsconf",
    # 		description = "Copy the feeds.conf",
    # 		command='''cp ~/feeds.conf ./feeds.conf''' ))

    # feed
    factory.addStep(
        ShellCommand(
            name="rmfeedlinks",
            description="Remove feed symlinks",
            command=["rm", "-rf", "package/feeds/"],
        )
    )

    factory.addStep(
        StringDownload(
            name="ccachecc",
            s='#!/bin/sh\nexec ${CCACHE} ${CCC} "$@"\n',
            workerdest="../ccache_cc.sh",
            mode=0o755,
        )
    )

    factory.addStep(
        StringDownload(
            name="ccachecxx",
            s='#!/bin/sh\nexec ${CCACHE} ${CCXX} "$@"\n',
            workerdest="../ccache_cxx.sh",
            mode=0o755,
        )
    )

    if external_targets:
        factory.addStep(
            FileDownload(
                name="Transfer master feeds.conf to worker feeds.conf.default",
                mastersrc=source_git / "feeds.conf",
                workerdest="feeds.conf.default",
                haltOnFailure=True,
            )
        )

    # Git SSH
    if git_ssh and git_ssh_key:
        factory.addStep(
            StringDownload(
                name="dlgitclonekey",
                s=git_ssh_key,
                workerdest="../git-clone.key",
                mode=0o600,
            )
        )

        factory.addStep(
            ShellCommand(
                name="patchfeedsconf",
                description="Patching feeds.conf",
                command="sed -e 's#https://#ssh://git@#g' feeds.conf.default > feeds.conf",
                haltOnFailure=True,
            )
        )

    # feed
    factory.addStep(
        ShellCommand(
            name="updatefeeds",
            description="Updating feeds",
            command=["./scripts/feeds", "update"],
            env=MakeEnv(
                tryccache=True,
                overrides={
                    "GIT_SSH_COMMAND": Interpolate(
                        "ssh -o IdentitiesOnly=yes -o IdentityFile=%(kw:cwd)s/git-clone.key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no",
                        cwd=GetCwd,
                    )
                }
                if git_ssh and git_ssh_key
                else {},
            ),
            haltOnFailure=True,
        )
    )

    # Git SSH
    if git_ssh and git_ssh_key:
        factory.addStep(
            ShellCommand(
                name="rmfeedsconf",
                description="Removing feeds.conf",
                command=["rm", "feeds.conf"],
                haltOnFailure=True,
            )
        )

    # feed
    factory.addStep(
        ShellCommand(
            name="installfeeds",
            description="Installing feeds",
            command=["./scripts/feeds", "install", "-a"],
            env=MakeEnv(tryccache=True),
            haltOnFailure=True,
        )
    )
    for external_target in external_targets:
        factory.addStep(
            ShellCommand(
                name=f"Install external target {external_target}",
                command=["./scripts/feeds", "install", external_target],
                env=MakeEnv(tryccache=True),
                haltOnFailure=True,
            )
        )

    if len(ts) == 2:
        # seed config
        if config_seed:
            factory.addStep(
                StringDownload(
                    name="dlconfigseed",
                    s=config_seed + "\n",
                    workerdest=".config",
                    mode=0o644,
                )
            )

        # configure
        factory.addStep(
            ShellCommand(
                name="newconfig",
                description="Seeding .config",
                command=f"printf 'CONFIG_TARGET_{ts[0]}=y\\nCONFIG_TARGET_{ts[0]}_{ts[1]}=y\\n' >> .config",
            )
        )
        factory.addStep(
            ShellCommand(
                name="defconfig",
                description="Populating .config",
                command=["make", "defconfig"],
                env=MakeEnv(),
            )
        )
    else:
        factory.addStep(
            ShellCommand(
                name="delconfig",
                description="Removing .config",
                command=["rm", "-f", ".config"],
            )
        )
        factory.addStep(
            ShellCommand(
                name="gen_config",
                description=f"Use config generator for {ts[2]}",
                command=["./scripts/gen_config.sh", ts[2]],
            )
        )

    factory.addStep(
        ShellCommand(
            name="delbin",
            description="Removing output directory",
            command=["rm", "-rf", "bin/"],
        )
    )

    # check arch
    factory.addStep(
        ShellCommand(
            name="checkarch",
            description="Checking architecture",
            command=["grep", "-sq", "CONFIG_TARGET_%s=y" % (ts[0]), ".config"],
            logEnviron=False,
            want_stdout=False,
            want_stderr=False,
            haltOnFailure=True,
        )
    )

    # find libc suffix
    factory.addStep(
        SetPropertyFromCommand(
            name="libc",
            property="libc",
            description="Finding libc suffix",
            command=[
                "sed",
                "-ne",
                '/^CONFIG_LIBC=/ { s!^CONFIG_LIBC="\\(.*\\)"!\\1!; s!^musl$!!; s!.\\+!-&!p }',
                ".config",
            ],
        )
    )

    # install build key
    if usign_key:
        factory.addStep(
            StringDownload(
                name="dlkeybuildpub",
                description="Download public usign key",
                s=usign_sec_2_pub(usign_key, usign_comment),
                workerdest="key-build.pub",
                mode=0o644,
            )
        )

    # prepare dl
    factory.addStep(
        ShellCommand(
            name="dldir",
            description="Preparing dl/",
            command="mkdir -p $HOME/dl && rm -rf ./dl && ln -sf $HOME/dl ./dl",
            logEnviron=False,
            want_stdout=False,
        )
    )

    # prepare tar
    factory.addStep(
        ShellCommand(
            name="dltar",
            description="Building and installing GNU tar",
            command=[
                "make",
                Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                "tools/tar/compile",
                "V=s",
            ],
            env=MakeEnv(tryccache=True),
            haltOnFailure=True,
        )
    )

    # populate dl
    factory.addStep(
        ShellCommand(
            name="dlrun",
            description="Populating dl/",
            command=[
                "make",
                Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                "download",
                "V=s",
            ],
            env=MakeEnv(),
            logEnviron=False,
            locks=[dlLock.access("exclusive")],
        )
    )

    factory.addStep(
        ShellCommand(
            name="cleanbase",
            description="Cleaning base-files",
            command=["make", "package/base-files/clean", "V=s"],
        )
    )

    # build
    factory.addStep(
        ShellCommand(
            name="tools",
            description="Building and installing tools",
            command=[
                "make",
                Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                "tools/install",
                "V=s",
            ],
            env=MakeEnv(tryccache=True),
            haltOnFailure=True,
        )
    )

    factory.addStep(
        ShellCommand(
            name="toolchain",
            description="Building and installing toolchain",
            command=[
                "make",
                Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                "toolchain/install",
                "V=s",
            ],
            env=MakeEnv(),
            haltOnFailure=True,
        )
    )

    factory.addStep(
        ShellCommand(
            name="kmods",
            description="Building kmods",
            command=[
                "make",
                Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                "target/compile",
                "V=s",
                "IGNORE_ERRORS=n m",
                "BUILD_LOG=1",
            ],
            env=MakeEnv(),
            # env={'BUILD_LOG_DIR': 'bin/%s' %(ts[0])},
            haltOnFailure=True,
        )
    )

    # find kernel version
    factory.addStep(
        SetPropertyFromCommand(
            name="kernelversion",
            property="kernelversion",
            description="Finding the effective Kernel version",
            command="make --no-print-directory -C target/linux/ val.LINUX_VERSION val.LINUX_RELEASE val.LINUX_VERMAGIC | xargs printf '%s-%s-%s\\n'",
            env={"TOPDIR": Interpolate("%(kw:cwd)s/build", cwd=GetCwd)},
        )
    )

    factory.addStep(
        ShellCommand(
            name="pkgclean",
            description="Cleaning up package build",
            command=["make", "package/cleanup", "V=s"],
        )
    )

    factory.addStep(
        ShellCommand(
            name="pkgbuild",
            description="Building packages",
            command=[
                "make",
                Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                "package/compile",
                "V=s",
                "IGNORE_ERRORS=n m",
                "BUILD_LOG=1",
            ],
            env=MakeEnv(),
            # env={'BUILD_LOG_DIR': 'bin/%s' %(ts[0])},
            haltOnFailure=True,
        )
    )

    # factory.addStep(IfBuiltinShellCommand(
    factory.addStep(
        ShellCommand(
            name="pkginstall",
            description="Installing packages",
            command=[
                "make",
                Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                "package/install",
                "V=s",
            ],
            env=MakeEnv(),
            haltOnFailure=True,
        )
    )

    factory.addStep(
        ShellCommand(
            name="pkgindex",
            description="Indexing packages",
            command=[
                "make",
                Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                "package/index",
                "V=s",
                "CONFIG_SIGNED_PACKAGES=",
            ],
            env=MakeEnv(),
            haltOnFailure=True,
        )
    )

    if enable_kmod_archive:
        # embed kmod repository. Must happen before 'images'

        # find rootfs staging directory
        factory.addStep(
            SetPropertyFromCommand(
                name="stageroot",
                property="stageroot",
                description="Finding the rootfs staging directory",
                command=["make", "--no-print-directory", "val.STAGING_DIR_ROOT"],
                env={"TOPDIR": Interpolate("%(kw:cwd)s/build", cwd=GetCwd)},
            )
        )

        factory.addStep(
            ShellCommand(
                name="filesdir",
                description="Creating file overlay directory",
                command=["mkdir", "-p", "files/etc/opkg"],
                haltOnFailure=True,
            )
        )

        factory.addStep(
            ShellCommand(
                name="kmodconfig",
                description="Embedding kmod repository configuration",
                command=Interpolate(
                    "sed -e 's#^\\(src/gz .*\\)_core \\(.*\\)/packages$#&\\n\\1_kmods \\2/kmods/%(prop:kernelversion)s#' "
                    + "%(prop:stageroot)s/etc/opkg/distfeeds.conf > files/etc/opkg/distfeeds.conf"
                ),
                haltOnFailure=True,
            )
        )

    # factory.addStep(IfBuiltinShellCommand(
    factory.addStep(
        ShellCommand(
            name="images",
            description="Building and installing images",
            command=[
                "make",
                Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                "target/install",
                "V=s",
            ],
            env=MakeEnv(),
            haltOnFailure=True,
        )
    )

    factory.addStep(
        ShellCommand(
            name="buildinfo",
            description="Generating config.buildinfo, version.buildinfo and feeds.buildinfo",
            command="make -j1 buildinfo V=s || true",
            env=MakeEnv(),
            haltOnFailure=True,
        )
    )

    factory.addStep(
        ShellCommand(
            name="checksums",
            description="Calculating checksums",
            command=["make", "-j1", "checksum", "V=s"],
            env=MakeEnv(),
            haltOnFailure=True,
        )
    )

    if enable_kmod_archive:
        factory.addStep(
            ShellCommand(
                name="kmoddir",
                description="Creating kmod directory",
                command=[
                    "mkdir",
                    "-p",
                    Interpolate(
                        "bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/kmods/%(prop:kernelversion)s",
                        target=ts[0],
                        subtarget=ts[1],
                    ),
                ],
                haltOnFailure=True,
            )
        )

        factory.addStep(
            ShellCommand(
                name="kmodprepare",
                description="Preparing kmod archive",
                command=[
                    "rsync",
                    "--include=/kmod-*.ipk",
                    "--exclude=*",
                    "-va",
                    Interpolate(
                        "bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/packages/",
                        target=ts[0],
                        subtarget=ts[1],
                    ),
                    Interpolate(
                        "bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/kmods/%(prop:kernelversion)s/",
                        target=ts[0],
                        subtarget=ts[1],
                    ),
                ],
                haltOnFailure=True,
            )
        )

        factory.addStep(
            ShellCommand(
                name="kmodindex",
                description="Indexing kmod archive",
                command=[
                    "make",
                    Interpolate("-j%(kw:jobs)s", jobs=get_num_jobs),
                    "package/index",
                    "V=s",
                    "CONFIG_SIGNED_PACKAGES=",
                    Interpolate(
                        "PACKAGE_SUBDIRS=bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/kmods/%(prop:kernelversion)s/",
                        target=ts[0],
                        subtarget=ts[1],
                    ),
                ],
                env=MakeEnv(),
                haltOnFailure=True,
            )
        )

    # sign
    if ini.has_option("gpg", "key") or usign_key:
        factory.addStep(
            MasterShellCommand(
                name="signprepare",
                description="Preparing temporary signing directory",
                command=["mkdir", "-p", "%s/signing" % (work_dir)],
                haltOnFailure=True,
            )
        )

        factory.addStep(
            ShellCommand(
                name="signpack",
                description="Packing files to sign",
                command=Interpolate(
                    "find bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/ bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/kmods/ -mindepth 1 -maxdepth 2 -type f -name sha256sums -print0 -or -name Packages -print0 | xargs -0 tar -czf sign.tar.gz",
                    target=ts[0],
                    subtarget=ts[1],
                ),
                haltOnFailure=True,
            )
        )

        factory.addStep(
            FileUpload(
                workersrc="sign.tar.gz",
                masterdest="%s/signing/%s.%s.tar.gz" % (work_dir, ts[0], ts[1]),
                haltOnFailure=True,
            )
        )

        factory.addStep(
            MasterShellCommand(
                name="signfiles",
                description="Signing files",
                command=[
                    "%s/signall.sh" % (scripts_dir),
                    "%s/signing/%s.%s.tar.gz" % (work_dir, ts[0], ts[1]),
                ],
                env={"CONFIG_INI": getenv("BUILDMASTER_CONFIG", "./config.ini")},
                haltOnFailure=True,
            )
        )

        factory.addStep(
            FileDownload(
                name="dlsigntargz",
                mastersrc="%s/signing/%s.%s.tar.gz" % (work_dir, ts[0], ts[1]),
                workerdest="sign.tar.gz",
                haltOnFailure=True,
            )
        )

        factory.addStep(
            ShellCommand(
                name="signunpack",
                description="Unpacking signed files",
                command=["tar", "-xzf", "sign.tar.gz"],
                haltOnFailure=True,
            )
        )

    # upload
    factory.addStep(
        ShellCommand(
            name="dirprepare",
            description="Preparing upload directory structure",
            command=[
                "mkdir",
                "-p",
                Interpolate(
                    "tmp/upload/%(kw:prefix)stargets/%(kw:target)s/%(kw:subtarget)s",
                    target=ts[0],
                    subtarget=ts[1],
                    prefix=GetVersionPrefix,
                ),
            ],
            haltOnFailure=True,
        )
    )

    factory.addStep(
        ShellCommand(
            name="linkprepare",
            description="Preparing repository symlink",
            command=[
                "ln",
                "-s",
                "-f",
                Interpolate("../packages-%(kw:basever)s", basever=GetBaseVersion()),
                Interpolate(
                    "tmp/upload/%(kw:prefix)spackages", prefix=GetVersionPrefix
                ),
            ],
            doStepIf=IsNoMasterBuild,
            haltOnFailure=True,
        )
    )

    if enable_kmod_archive:
        factory.addStep(
            ShellCommand(
                name="kmoddirprepare",
                description="Preparing kmod archive upload directory",
                command=[
                    "mkdir",
                    "-p",
                    Interpolate(
                        "tmp/upload/%(kw:prefix)stargets/%(kw:target)s/%(kw:subtarget)s/kmods/%(prop:kernelversion)s",
                        target=ts[0],
                        subtarget=ts[1],
                        prefix=GetVersionPrefix,
                    ),
                ],
                haltOnFailure=True,
            )
        )

    factory.addStep(
        ShellCommand(
            name="dirupload",
            description="Uploading directory structure",
            command=["rsync", "-az"]
            + rsync_bin_defopts
            + ["tmp/upload/", "%s/" % (rsync_bin_url)],
            env={"RSYNC_PASSWORD": rsync_bin_key},
            haltOnFailure=True,
            logEnviron=False,
        )
    )

    # download remote sha256sums to 'target-sha256sums'
    factory.addStep(
        ShellCommand(
            name="target-sha256sums",
            description="Fetching remote sha256sums for target",
            command=["rsync", "-z"]
            + rsync_bin_defopts
            + [
                Interpolate(
                    "%(kw:rsyncbinurl)s/%(kw:prefix)stargets/%(kw:target)s/%(kw:subtarget)s/sha256sums",
                    rsyncbinurl=rsync_bin_url,
                    target=ts[0],
                    subtarget=ts[1],
                    prefix=GetVersionPrefix,
                ),
                "target-sha256sums",
            ],
            env={"RSYNC_PASSWORD": rsync_bin_key},
            logEnviron=False,
            haltOnFailure=False,
            flunkOnFailure=False,
            warnOnFailure=False,
        )
    )

    # build list of files to upload
    factory.addStep(
        FileDownload(
            name="dlsha2rsyncpl",
            mastersrc=scripts_dir + "/sha2rsync.pl",
            workerdest="../sha2rsync.pl",
            mode=0o755,
        )
    )

    factory.addStep(
        ShellCommand(
            name="buildlist",
            description="Building list of files to upload",
            command=[
                "../sha2rsync.pl",
                "target-sha256sums",
                Interpolate(
                    "bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/sha256sums",
                    target=ts[0],
                    subtarget=ts[1],
                ),
                "rsynclist",
            ],
            haltOnFailure=True,
        )
    )

    factory.addStep(
        FileDownload(
            name="dlrsync.sh",
            mastersrc=scripts_dir + "/rsync.sh",
            workerdest="../rsync.sh",
            mode=0o755,
        )
    )

    # upload new files and update existing ones
    factory.addStep(
        ShellCommand(
            name="targetupload",
            description="Uploading target files",
            command=[
                "../rsync.sh",
                "--exclude=/kmods/",
                "--files-from=rsynclist",
                "--delay-updates",
                "--partial-dir=.~tmp~%s~%s" % (ts[0], ts[1]),
            ]
            + rsync_bin_defopts
            + [
                "-a",
                Interpolate(
                    "bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/",
                    target=ts[0],
                    subtarget=ts[1],
                ),
                Interpolate(
                    "%(kw:rsyncbinurl)s/%(kw:prefix)stargets/%(kw:target)s/%(kw:subtarget)s/",
                    rsyncbinurl=rsync_bin_url,
                    target=ts[0],
                    subtarget=ts[1],
                    prefix=GetVersionPrefix,
                ),
            ],
            env={"RSYNC_PASSWORD": rsync_bin_key},
            haltOnFailure=True,
            logEnviron=False,
        )
    )

    # delete files which don't exist locally
    factory.addStep(
        ShellCommand(
            name="targetprune",
            description="Pruning target files",
            command=[
                "../rsync.sh",
                "--exclude=/kmods/",
                "--delete",
                "--existing",
                "--ignore-existing",
                "--delay-updates",
                "--partial-dir=.~tmp~%s~%s" % (ts[0], ts[1]),
            ]
            + rsync_bin_defopts
            + [
                "-a",
                Interpolate(
                    "bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/",
                    target=ts[0],
                    subtarget=ts[1],
                ),
                Interpolate(
                    "%(kw:rsyncbinurl)s/%(kw:prefix)stargets/%(kw:target)s/%(kw:subtarget)s/",
                    rsyncbinurl=rsync_bin_url,
                    target=ts[0],
                    subtarget=ts[1],
                    prefix=GetVersionPrefix,
                ),
            ],
            env={"RSYNC_PASSWORD": rsync_bin_key},
            haltOnFailure=True,
            logEnviron=False,
        )
    )

    if enable_kmod_archive:
        factory.addStep(
            ShellCommand(
                name="kmodupload",
                description="Uploading kmod archive",
                command=[
                    "../rsync.sh",
                    "--delete",
                    "--delay-updates",
                    "--partial-dir=.~tmp~%s~%s" % (ts[0], ts[1]),
                ]
                + rsync_bin_defopts
                + [
                    "-a",
                    Interpolate(
                        "bin/targets/%(kw:target)s/%(kw:subtarget)s%(prop:libc)s/kmods/%(prop:kernelversion)s/",
                        target=ts[0],
                        subtarget=ts[1],
                    ),
                    Interpolate(
                        "%(kw:rsyncbinurl)s/%(kw:prefix)stargets/%(kw:target)s/%(kw:subtarget)s/kmods/%(prop:kernelversion)s/",
                        rsyncbinurl=rsync_bin_url,
                        target=ts[0],
                        subtarget=ts[1],
                        prefix=GetVersionPrefix,
                    ),
                ],
                env={"RSYNC_PASSWORD": rsync_bin_key},
                haltOnFailure=True,
                logEnviron=False,
            )
        )

    if rsync_src_url:
        factory.addStep(
            ShellCommand(
                name="sourcelist",
                description="Finding source archives to upload",
                command="find dl/ -maxdepth 1 -type f -not -size 0 -not -name '.*' -newer .config -printf '%f\\n' > sourcelist",
                haltOnFailure=True,
            )
        )

        factory.addStep(
            ShellCommand(
                name="sourceupload",
                description="Uploading source archives",
                command=[
                    "../rsync.sh",
                    "--files-from=sourcelist",
                    "--size-only",
                    "--delay-updates",
                ]
                + rsync_src_defopts
                + [
                    Interpolate(
                        "--partial-dir=.~tmp~%(kw:target)s~%(kw:subtarget)s~%(prop:workername)s",
                        target=ts[0],
                        subtarget=ts[1],
                    ),
                    "-a",
                    "dl/",
                    "%s/" % (rsync_src_url),
                ],
                env={"RSYNC_PASSWORD": rsync_src_key},
                haltOnFailure=True,
                logEnviron=False,
            )
        )

    if False:
        factory.addStep(
            ShellCommand(
                name="packageupload",
                description="Uploading package files",
                command=[
                    "../rsync.sh",
                    "--delete",
                    "--delay-updates",
                    "--partial-dir=.~tmp~%s~%s" % (ts[0], ts[1]),
                    "-a",
                ]
                + rsync_bin_defopts
                + ["bin/packages/", "%s/packages/" % (rsync_bin_url)],
                env={"RSYNC_PASSWORD": rsync_bin_key},
                haltOnFailure=False,
                logEnviron=False,
            )
        )

    # logs
    if False:
        factory.addStep(
            ShellCommand(
                name="upload",
                description="Uploading logs",
                command=[
                    "../rsync.sh",
                    "--delete",
                    "--delay-updates",
                    "--partial-dir=.~tmp~%s~%s" % (ts[0], ts[1]),
                    "-az",
                ]
                + rsync_bin_defopts
                + ["logs/", "%s/logs/%s/%s/" % (rsync_bin_url, ts[0], ts[1])],
                env={"RSYNC_PASSWORD": rsync_bin_key},
                haltOnFailure=False,
                alwaysRun=True,
                logEnviron=False,
            )
        )

    factory.addStep(
        ShellCommand(
            name="df",
            description="Reporting disk usage",
            command=["df", "-h", "."],
            env={"LC_ALL": "C"},
            haltOnFailure=False,
            alwaysRun=True,
        )
    )

    factory.addStep(
        ShellCommand(
            name="ccachestat",
            description="Reporting ccache stats",
            command=["ccache", "-s"],
            env=MakeEnv(overrides={"PATH": ["${PATH}", "./staging_dir/host/bin"]}),
            want_stderr=False,
            haltOnFailure=False,
            flunkOnFailure=False,
            warnOnFailure=False,
            alwaysRun=True,
        )
    )

    from buildbot.config import BuilderConfig

    c["builders"].append(
        BuilderConfig(
            name=target,
            workernames=workerNames,
            factory=factory,
            nextBuild=GetNextBuild,
        )
    )
