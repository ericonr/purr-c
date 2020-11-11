i18n = import('i18n')
i18n.gettext(
  meson.project_name(),
  args: '--directory=' + meson.source_root(),
  preset: 'glib',
)

add_project_arguments(
  '-DGETTEXT_PACKAGE="@0@"'.format(meson.project_name()),
  '-DGETTEXT_DIR="@0@"'.format(get_option('prefix') / get_option('localedir')),
  language:'c'
)
