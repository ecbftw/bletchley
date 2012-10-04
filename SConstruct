import sys
import os
sys.dont_write_bytecode = True
from bletchley_version import BLETCHLEY_VERSION

cflags = '-std=gnu99 -pedantic -Wall -D_FILE_OFFSET_BITS=64 -fvisibility=hidden'
cflags += ' -DBLETCHLEY_VERSION=\'"%s"\'' % BLETCHLEY_VERSION
cflags += ' -ggdb'

#lib_src = ['lib/bletchley.c',
#           'lib/winsec.c',
#           'lib/range_list.c',
#           'lib/lru_cache.c',
#           'lib/void_stack.c']

cc=os.environ.get('CC', 'gcc')
env = Environment(ENV=os.environ,
                  CC=cc,
                  CFLAGS=cflags,
                  CPPPATH=['include', '/usr/local/include'],
                  LIBPATH=['lib', '/usr/local/lib'],
                  LIBS=[])

# Libraries
#libbletchley_static = env.Library(lib_src)
#libbletchley = env.SharedLibrary(lib_src, LIBS=['m','pthread', 'talloc'], 
#                                 LINKFLAGS="-shared -fPIC -Wl,-soname,libbletchley.so.%s" % BLETCHLEY_VERSION)


# Executable binaries
bletchley_nextrand = env.Program('bin/bletchley-nextrand', ['src/nextrand.c'])


# Documentation
#  This only needs to be run during the release/packaging process
#man_fixup = "|sed 's/.SH DESCRIPTION/\\n.SH DESCRIPTION/'"
#man_builder = Builder(action='docbook2x-man --to-stdout $SOURCE'
#                      + man_fixup + '| gzip -9 > $TARGET',
#                      suffix = '.gz',
#                      src_suffix = '.docbook')
#env['BUILDERS']['ManPage'] = man_builder

#man_bletchley = env.ManPage('doc/bletchley.1.docbook')
#man_bletchley_recover = env.ManPage('doc/bletchley-recover.1.docbook')
#man_bletchley_timeline = env.ManPage('doc/bletchley-timeline.1.docbook')

# Installation
prefix     = os.environ.get('PREFIX','/usr/local')+'/'
destdir    = os.environ.get('DESTDIR','')
bindir     = os.environ.get('BINDIR', prefix + 'bin')
libdir     = os.environ.get('LIBDIR', prefix + 'lib')
includedir = os.environ.get('INCLUDEDIR', prefix + 'include')
mandir     = os.environ.get('MANDIR', prefix + 'man')

install_items = [destdir + bindir]

env.Install(destdir+bindir, [bletchley_nextrand, 'bin/bletchley-analyze'])
#libinstall = env.Install(destdir+libdir, [libbletchley, libbletchley_static])
#env.Install(destdir+includedir+'/bletchley', Glob('include/*.h'))
#env.Install(destdir+mandir+'/man1', [man_bletchley, man_bletchley_recover,
#                                     man_bletchley_timeline])
#if os.getuid() == 0:
#   env.AddPostAction(libinstall, 'ldconfig')

if sys.version_info[0] == 2:
   install_items.append('bletchley-python2.log')
   env.Command('bletchley-python2.log', Glob('lib/bletchley/*.py')+Glob('lib/bletchley/PaddingOracle/*.py'),
               "python bletchley-distutils install --root=/%s | tee bletchley-python2.log" % destdir)

python_path = os.popen('which python3').read()
if python_path != '':
   install_items.append('bletchley-python3.log')
   env.Command('bletchley-python3.log', Glob('lib/bletchley/*.py')+Glob('lib/bletchley/PaddingOracle/*.py'),
               "python3 bletchley-distutils install --root=/%s | tee bletchley-python3.log" % destdir)

# API documentation
#bletchley_doc = env.Command('doc/devel/bletchley/index.html', 
#                            Glob('lib/*.c')+Glob('include/*.h')+['doc/devel/Doxyfile.bletchley'],
#                            'doxygen doc/devel/Doxyfile.bletchley')
#pybletchley_doc = env.Command('doc/devel/pybletchley/index.html', 
#                              Glob('python/pybletchley/*.py')+['doc/devel/Doxyfile.pybletchley', bletchley_doc],
#                              'doxygen doc/devel/Doxyfile.pybletchley')


# User Friendly Targets
env.Alias('bin', [bletchley_nextrand])
#env.Alias('doc', [man_bletchley,man_bletchley_recover,man_bletchley_timeline])
#env.Alias('doc-devel', [bletchley_doc, pybletchley_doc])
env.Alias('install', install_items)

Default('bin')
