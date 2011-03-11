require 'mkmf'

#find_library("acl","acl_get_file")
#find_library("acl","acl_get_fd")

dir_config("acl")

unless(find_header("sys/acl.h") && 
	find_header("acl/libacl.h") && 
	find_library("acl",nil,"/usr/lib"))
abort("libacl is missing.")
end

have_header("pwd.h") if find_header("pwd.h")
have_header("grp.h") if find_header("grp.h")

unless have_func("rb_string_value_cstr","ruby.h")
	abort("missing VALUE to char convert!")
end

$CFLAGS += " -Wall"

create_makefile("acl")
