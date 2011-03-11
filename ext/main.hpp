#ifndef __RubyAclMain_H__
#define __RubyAclMain_H__
#include <ruby.h>
#include <sys/acl.h>
#include <acl/libacl.h>

#include <pwd.h>
#include <grp.h>

extern VALUE rb_cAcl,rb_cAclEntry;

void Init_aclEntry(VALUE m);
//template <typename T>
//VALUE wrap(T *arg){ return Qnil;};
template <typename T>
VALUE wrap(T arg){ return Qnil;};
template <typename T>
T wrap(const VALUE &arg){};

struct ruby_acl_entry{
	acl_t acl;
	acl_entry_t entry;
};
inline void ruby_acl_free(ruby_acl_entry* entry){
	acl_free(entry->acl);
	free(entry);
}

template <>
inline VALUE wrap< acl_entry_t >(acl_entry_t entry )
{
	ruby_acl_entry *obj = new ruby_acl_entry;
	acl_entry_t newentry;
	acl_t acl = acl_init(0);
	obj->acl = acl;
	acl_create_entry(&acl,&newentry);
	obj->entry =newentry;
	acl_copy_entry(newentry,entry);
	return Data_Wrap_Struct(rb_cAclEntry, NULL, ruby_acl_free, obj);
}

template <>
inline VALUE wrap< acl_t >(acl_t file )
{
	return Data_Wrap_Struct(rb_cAcl, NULL, acl_free, file);
}

template <>
inline acl_t wrap< acl_t >(const VALUE &vfile)
{
	if ( ! rb_obj_is_kind_of(vfile, rb_cAcl) )
		return NULL;
	acl_t file;
  Data_Get_Struct( vfile, __acl_ext, file);
	return file;
}


template <>
inline acl_entry_t wrap< acl_entry_t >(const VALUE &vfile)
{
	if ( ! rb_obj_is_kind_of(vfile, rb_cAclEntry) )
		return NULL;
	ruby_acl_entry *obj;
  Data_Get_Struct( vfile, ruby_acl_entry, obj);
	return obj->entry;
}

#endif /* __RubyAclMain_H__ */

