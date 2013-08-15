import sys
import os

cflags = '-std=gnu99 -pedantic -Wall -D_FILE_OFFSET_BITS=64'


latest_release='0.0.1'
source_targets=('src-trunk', 'src-0.0.1',)
all_targets = source_targets


def parse_target(target):
    chunks = target.split('-')
    if len(chunks) != 2:
        return None
    return chunks

def version2input(version):
    if version == 'trunk':
        return 'trunk/'
    else:
        return 'releases/%s/' % version


export_cmds='''
rm -rf .export
svn export --depth files https://bletchley.googlecode.com/svn/ .export
svn export https://bletchley.googlecode.com/svn/%(path)s .export/%(path)s
'''

version_cmds='''
echo 'BLETCHLEY_VERSION="%(version)s"' > .export/%(path)s/bletchley_version.py
'''

svnversion_cmds='''
svn info https://bletchley.googlecode.com/svn/trunk/\
  | grep "Last Changed Rev:" | cut -d' ' -f 4 \
  | sed 's/^/BLETCHLEY_VERSION="%(latest_release)s.svn/' | sed 's/$/"/' > .export/%(path)s/bletchley_version.py
'''

cleanup_cmds='''
rm -rf .export
'''

source_cmds='''
mv %s .export/%s
cd .export/%s && scons doc
cd .export && tar cf %s.tar %s && gzip -9 %s.tar
mv .export/%s.tar.gz .
'''+cleanup_cmds


def generate_cmds(source, target, env, for_signature):
    ret_val = ''
    input_prefix = str(source[0])+'/'

    for t in target:
        ttype,version = parse_target(str(t))
        t_base = 'bletchley-%s-%s' % (ttype, version)

        if ttype == 'src':
            ret_val += source_cmds % (input_prefix, t_base, t_base, t_base,
                                      t_base, t_base, t_base)
    return ret_val


release_builder = Builder(generator = generate_cmds,
                          suffix = '',
                          src_suffix = '',
                          prefix='')

env = Environment()
env['BUILDERS']['Release'] = release_builder

if len(COMMAND_LINE_TARGETS) == 0:
    print('Acceptable targets: %s' % repr(all_targets))

for target in COMMAND_LINE_TARGETS:
    if target not in all_targets:
        print('ERROR: cannot build "%s".  Acceptable targets: %s'
              % (target, repr(all_targets)))
        sys.exit(1)
    AlwaysBuild(target)
    ttype,version = parse_target(target)

    params = {'path':version2input(version), 
              'version':version,
              'latest_release':latest_release}
    env.Execute(export_cmds % params)
    if version == 'trunk':
        print env.Execute(svnversion_cmds % params)
    else:
        env.Execute(version_cmds % params)
    env.Release(target, Dir('.export/'+params['path']))

Default(None)
