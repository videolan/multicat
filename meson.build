project('multicat', 'c',
  version: '2.4',
  default_options: ['c_std=gnu99',
                      'warning_level=3',
                      'buildtype=release',
                      'b_ndebug=if-release'],
  meson_version: '>= 0.49.0')

cc = meson.get_compiler('c')

has_format_security = cc.has_argument('-Wformat-security')
if has_format_security
    add_project_arguments('-Wformat-security', language : 'c')
endif

has_omit_fp = cc.has_argument('-fomit-frame-pointer')
if has_omit_fp
    add_project_arguments('-fomit-frame-pointer', language : 'c')
endif

add_project_arguments('-D_ISOC99_SOURCE', language : 'c')
add_project_arguments('-D_BSD_SOURCE', language : 'c')
add_project_arguments('-D_DEFAULT_SOURCE', language : 'c')

threads_dep = dependency('threads', required: false)

multicat_pie = false
hardened_args = []
if get_option('hardened').enabled()
    hardened_args = ['-Wl,-z,relro', '-Wl,-z,now']
    add_project_arguments('-fstack-protector', language: 'c')
    multicat_pie = true
if get_option('optimization') != '0'
    add_project_arguments('-D_FORTIFY_SOURCE=2', language: 'c')
endif
endif

bitstream_dep = dependency('bitstream', required: true)

executable('multicat',
           ['multicat.c', 'util.c'],
           install: true,
           link_args: [hardened_args],
           pie: multicat_pie,
           dependencies: [threads_dep, bitstream_dep])

executable('ingests',
           ['ingests.c', 'util.c'],
           install: true,
           link_args: [hardened_args],
           pie: multicat_pie,
           dependencies: bitstream_dep)

executable('aggregartp',
           ['aggregartp.c', 'util.c'],
           install: true,
           link_args: [hardened_args],
           pie: multicat_pie,
           dependencies: [threads_dep, bitstream_dep])

executable('reordertp',
           ['reordertp.c', 'util.c'],
           install: true,
           link_args: [hardened_args],
           pie: multicat_pie,
           dependencies: [threads_dep, bitstream_dep])

executable('offsets',
           ['offsets.c', 'util.c'],
           install: true,
           link_args: [hardened_args],
           pie: multicat_pie,
           dependencies: bitstream_dep)

executable('lasts',
           'lasts.c',
           install: true,
           link_args: [hardened_args],
           pie: multicat_pie,
           dependencies: bitstream_dep)

executable('multicat_validate',
           ['multicat_validate.c', 'util.c'],
           install: true,
           link_args: [hardened_args],
           pie: multicat_pie,
           dependencies: bitstream_dep)

executable('multilive',
           ['multilive.c', 'util.c'],
           install: true,
           link_args: [hardened_args],
           pie: multicat_pie,
           dependencies: [threads_dep, bitstream_dep])

executable('smooths',
           ['smooths.c', 'util.c'],
           install: true,
           link_args: [hardened_args],
           pie: multicat_pie,
           dependencies: [threads_dep, bitstream_dep])

install_man(['multicat.1', 'ingests.1', 'aggregartp.1', 'reordertp.1', 'offsets.1', 'lasts.1'])
