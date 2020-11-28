project('purr-c', 'c',
  version : '0.1',
  default_options : ['warning_level=3'])

compiler = meson.get_compiler('c')

subdir('po')

bearssl = compiler.find_library('bearssl', required: true)

gnu_source = '#define _GNU_SOURCE'
gnu_progname = compiler.has_header_symbol(
  'errno.h',
  'program_invocation_short_name',
  prefix: gnu_source
)
bsd_progname = compiler.has_header_symbol('stdlib.h', 'getprogname')
sock_cloexec = compiler.has_header_symbol('sys/socket.h', 'SOCK_CLOEXEC')
pipe2 = compiler.has_header_symbol('unistd.h', 'pipe2', prefix: gnu_source)

args = []
if bsd_progname
  args += '-DHAVE_GETPROGNAME'
elif gnu_progname
  args += '-DHAVE_PROG_INVOCATION'
elif
  error('no progname impl')
endif
if sock_cloexec
  args += '-DHAVE_SOCK_CLOEXEC_H'
endif
if pipe2
  args += '-DHAVE_PIPE2'
endif
add_project_arguments(args, language: 'c')

purrlib = static_library(
  'purrlib',
  'mmap_file.c',
  'gemini.c',
  'read_certs.c',
  'urls.c',
  'files.c',
  'pager.c',
  'comm.c',
  'formats.c',
  'encrypt.c',
  'socket.c',
  'compat.c',
)

executable('purr', 'purr.c', link_with: purrlib, dependencies: bearssl, install: true)
executable('gemi', 'gemi.c', link_with: purrlib, dependencies: bearssl, install: true)

command = 'ln -sf purr ${DESTDIR}/${MESON_INSTALL_PREFIX}/@0@/@1@'
meson.add_install_script('sh', '-c', command.format(get_option('bindir'), 'meow'))
meson.add_install_script('sh', '-c', command.format(get_option('bindir'), 'meowd'))

tests = executable('tests', 'tests.c', link_with: purrlib, dependencies: bearssl, install: false)
test('library-tests', tests)
test(
  'executable-tests',
  find_program('test.sh'),
  args: meson.current_source_dir() / 'README.md',
  workdir: meson.current_build_dir()
)
