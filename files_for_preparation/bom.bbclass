# Copyright (c) 2020 LG Electronics, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# This class adds write_bom_info and write_abi_xml_data,
# Each of them can be run by bitake --runall option.
# They are useful to verify build output specification.
 
do_write_bom_info[nostamp] = "1"
addtask write_bom_info
python do_write_bom_info() {
    import json
    # We want one recipe per line, starting with arch and recipe keys,
    # so that it's easy to sort and compare them
    class BomJSONEncoder(json.JSONEncoder):
        def iterencode(self, obj, _one_shot=True):
            if isinstance(obj, dict):
                output = []
                if "arch" in obj.keys() and "recipe" in obj.keys():
                    output.append(json.dumps("arch") + ": " + self.encode(obj["arch"]))
                    output.append(json.dumps("recipe") + ": " + self.encode(obj["recipe"]))
                for key, value in sorted(obj.items()):
                    if key == "arch" or key == "recipe":
                        continue
                    output.append(json.dumps(key) + ": " + self.encode(value))
                return "{" + ",".join(output) + "}"
            else:
                return json.JSONEncoder().iterencode(obj, _one_shot)
 
    jsondata = {}
    jsondata["src_path"] = d.getVar("S", True)
    jsondata["src_uri"] = d.getVar("SRC_URI", True)
    jsondata["srcrev"] = "".join(d.getVar("SRCREV", True).split())
    jsondata["recipe"] = d.getVar("PN", True)
    jsondata["file"] = d.getVar("FILE", True)[len(d.getVar("TOPDIR", True)):]
    jsondata["arch"] = d.getVar("PACKAGE_ARCH", True)
    jsondata["author"] = d.getVar("AUTHOR", True)
    license = d.getVar("LICENSE", True)
    license_flags = d.getVar("LICENSE_FLAGS", True)
    packages = d.getVar("PACKAGES", True)
    jsondata["license"] = license
    jsondata["license_flags"] = license_flags
    jsondata["packages"] = packages
    pkg_lic = {}
    if packages:
        for pkg in packages.split():
            lic = d.getVar("LICENSE_%s" % pkg, True)
            if lic and lic != license:
                pkg_lic[pkg] = lic
    jsondata["pkg_lic"] = pkg_lic
    jsondata["pe"] = d.getVar("PE", True)
    jsondata["pv"] = d.getVar("PV", True)
    jsondata["pr"] = d.getVar("PR", True)
    jsondata["extendprauto"] = d.getVar("EXTENDPRAUTO", True)
    jsondata["extendpkgv"] = d.getVar("EXTENDPKGV", True)
    jsondata["description"] = d.getVar("DESCRIPTION", True)
    jsondata["summary"] = d.getVar("SUMMARY", True)
    jsondata["cve_check_whitelist "] = d.getVar("CVE_CHECK_WHITELIST", True)

    datafile = os.path.join(d.getVar("TOPDIR", True), "bom.json")
    lock = bb.utils.lockfile(datafile + '.lock')
    with open(datafile, "a") as f:
        json.dump(jsondata, f, sort_keys=True, cls=BomJSONEncoder)
        f.write(',\n')
    bb.utils.unlockfile(lock)
}


python do_dumptasks() {
    
    #Dump BitBake tasks to ${TOPDIR}/dumped_tasks/${PF}.task_name.
    
    import os
    import bb

    # dump_tasks folder gathers all dumped tasks
    ar_outdir = os.path.join(d.getVar('TOPDIR', True), "dumped_tasks")  
    ar_dumptasks = ["do_configure", "do_compile"] 
    pf = d.getVar('PF', True)

    bb.utils.mkdirhier(ar_outdir)

    for task in ar_dumptasks:
        # Do not export tasks that are set to do not run
        if d.getVarFlag(task, 'noexec') == '1':
            bb.warn('%s: skipping task %s: [noexec]' % (pf, task))
            continue

        dumpfile = os.path.join(ar_outdir, '%s.%s' % (pf, task))
        bb.note('Dumping task %s into %s' % (task, dumpfile))

        # We assume the task as a shell script and then check if it is
        # actually a Python script.
        emit_func = bb.data.emit_func
        if d.getVarFlag(task, 'python') == '1':
            emit_func = bb.data.emit_func_python

        try:
            with open(dumpfile, 'w') as f:
                emit_func(task, f, d)
        except Exception as e:
            bb.fatal('%s: Cannot export %s: %s' % (pf, task, e))
}


python do_archive() {
    import os
    import subprocess

    topdir = d.getVar('TOPDIR')
    s = d.getVar('S')
    pf = d.getVar('PF')

    sources_dir = os.path.join(topdir, 'sources')
    if not os.path.exists(sources_dir):
        os.makedirs(sources_dir)

    output_filename = os.path.join(sources_dir, f"{pf}.tar.gz")
    script_path = os.path.join(d.getVar('WORKDIR'), 'archive_source.py')

    # Run the Python script to create the archive
    subprocess.run(['python3', script_path, s, output_filename], check=True)
}


# do_dumptasks 
addtask do_dumptasks after do_configure before do_compile
addtask do_archive after do_configure before do_compile
