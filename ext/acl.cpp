#include "main.hpp"

VALUE rb_cAcl,rb_cAclEntry;

#define _self wrap<acl_t>(self)

VALUE ACL_alloc(VALUE self)
{
	acl_t acl = acl_init(1);
	return wrap(acl);
}

VALUE IO_acl(VALUE self)
{
	acl_t acl = acl_get_fd(NUM2INT(rb_funcall(self,rb_intern("to_i"),0)));
	return acl ? wrap(acl) : Qnil;
}

VALUE IO_set_acl(VALUE self,VALUE acl)
{
	acl_set_fd(NUM2INT(rb_funcall(self,rb_intern("to_i"),0)),wrap<acl_t>(acl));
	return acl;
}
VALUE File_single_access_acl(VALUE self,VALUE name)
{
	acl_t acl = acl_get_file(rb_string_value_cstr(&name), ACL_TYPE_ACCESS);
	return acl ? wrap(acl) : Qnil;
}

VALUE File_single_default_acl(VALUE self,VALUE name)
{
	acl_t acl = acl_get_file(rb_string_value_cstr(&name), ACL_TYPE_DEFAULT);
	return acl ? wrap(acl) : Qnil;
}

VALUE File_single_set_access_acl(VALUE self,VALUE name,VALUE acl)
{
	acl_set_file(rb_string_value_cstr(&name), ACL_TYPE_ACCESS,wrap<acl_t>(acl));
	return acl;
}

VALUE File_single_set_default_acl(VALUE self,VALUE name,VALUE acl)
{
	acl_set_file(rb_string_value_cstr(&name), ACL_TYPE_DEFAULT,wrap<acl_t>(acl));
	return acl;
}

VALUE File_access_acl(VALUE self)
{
	VALUE name = rb_get_path(self);
	acl_t acl = acl_get_file(rb_string_value_cstr(&name), ACL_TYPE_ACCESS);
	return acl ? wrap(acl) : Qnil;
}

VALUE File_set_access_acl(VALUE self,VALUE acl)
{
	if(rb_obj_is_kind_of(acl,rb_cAcl)){
		VALUE name = rb_get_path(self);
		acl_set_file(rb_string_value_cstr(&name), ACL_TYPE_ACCESS,wrap<acl_t>(acl));
	}else
		rb_raise(rb_eTypeError,"exepted %s!",rb_class2name(rb_cAcl));
	return acl;
}

VALUE File_default_acl(VALUE self)
{
	VALUE name = rb_get_path(self);
	acl_t acl = acl_get_file(rb_string_value_cstr(&name), ACL_TYPE_DEFAULT);
	return acl ? wrap(acl) : Qnil;
}

VALUE File_set_default_acl(VALUE self,VALUE acl)
{
	if(rb_obj_is_kind_of(acl,rb_cAcl)){
		VALUE name = rb_get_path(self);
		acl_set_file(rb_string_value_cstr(&name), ACL_TYPE_DEFAULT,wrap<acl_t>(acl));
	}else
		rb_raise(rb_eTypeError,"exepted %s!",rb_class2name(rb_cAcl));
	return acl;
}


VALUE ACL_size(VALUE self)
{
	return INT2NUM(acl_entries(_self));
}

VALUE ACL_valid(VALUE self)
{	
//	int i =	acl_check(_self,NULL);
//	if(i)
//		rb_warn("%d:%s",i,acl_error(i));
	return acl_valid(_self)==0 ? Qtrue : Qfalse;
}


VALUE ACL_inspect(VALUE self)
{
	return rb_str_new2(acl_to_text(_self,NULL));
}

VALUE ACL_entries(VALUE self)
{
	RETURN_ENUMERATOR(self,0,NULL);
	VALUE result = rb_ary_new();
	acl_entry_t entry;
	int i = -1;
	for(int id = ACL_FIRST_ENTRY;i > 0;id=ACL_NEXT_ENTRY){
		i = acl_get_entry(_self,id, &entry);
		if(i>0){
			VALUE temp = wrap(entry);
			rb_yield(temp);
			rb_ary_push(result,temp);
		}
	}
	return result;
}

VALUE ACL_add(VALUE self,VALUE entry)
{
	acl_entry_t newentry;
	acl_t acl = _self;
	int i = -1;
	bool found_mask=false;
	acl_tag_t tag,oldtag;
	acl_get_tag_type(wrap<acl_entry_t>(entry),&tag);
	switch(tag){
	case ACL_USER_OBJ:
	case ACL_GROUP_OBJ:
	case ACL_OTHER:
	case ACL_MASK:
		for(int id = ACL_FIRST_ENTRY;i>0;id=ACL_NEXT_ENTRY){
			i = acl_get_entry(_self,id, &newentry);
			if(i){
				acl_get_tag_type(newentry,&oldtag);
				if(tag==oldtag)
					acl_delete_entry(_self,newentry);
			}
		}
		break;
	case ACL_USER:
	case ACL_GROUP:
	
		for(int id = ACL_FIRST_ENTRY;i>0;id=ACL_NEXT_ENTRY){
			i = acl_get_entry(_self,id, &newentry);
			if(i>0){
				acl_get_tag_type(newentry,&oldtag);
				if(oldtag == ACL_MASK)
					found_mask=true;
				if((tag==oldtag) && (acl_get_qualifier(newentry)==acl_get_qualifier(wrap<acl_entry_t>(entry))))
					acl_delete_entry(_self,newentry);
			}
		}
		if(!found_mask)
			acl_calc_mask(&acl);
	}
	acl_create_entry(&acl,&newentry);
	acl_copy_entry(newentry,wrap<acl_entry_t>(entry));
	return self;
}

VALUE ACL_get(VALUE self,VALUE nr)
{
	if(acl_entries(_self) <= NUM2INT(nr))
		return Qnil;
	acl_entry_t entry;
	int i = 0;
	for(int id = ACL_FIRST_ENTRY;i <= NUM2INT(nr) ;i++){
		acl_get_entry(_self,id, &entry);
		id=ACL_NEXT_ENTRY;
	}
	return wrap(entry);
}

VALUE ACL_delete_if(VALUE self)
{
	RETURN_ENUMERATOR(self,0,NULL);
	VALUE result = rb_ary_new();
	acl_entry_t entry;
	int i = -1;
	for(int id = ACL_FIRST_ENTRY;i>0;id=ACL_NEXT_ENTRY){
		i = acl_get_entry(_self,id, &entry);
		if(i>0){
			VALUE temp = wrap(entry);
			if(RTEST(rb_yield(temp))){
				acl_delete_entry(_self,entry);
				rb_ary_push(result,temp);
			}
		}
	}
	return result;
}

extern "C" void Init_acl(void){
	rb_cAcl = rb_define_class("ACL",rb_cObject);
	rb_define_alloc_func(rb_cAcl,ACL_alloc);
	rb_define_method(rb_cIO,"acl",RUBY_METHOD_FUNC(IO_acl),0);
	rb_define_method(rb_cIO,"acl=",RUBY_METHOD_FUNC(IO_set_acl),1);
	rb_define_method(rb_cFile,"access_acl",RUBY_METHOD_FUNC(File_access_acl),0);
	rb_define_method(rb_cFile,"access_acl=",RUBY_METHOD_FUNC(File_set_access_acl),1);
	rb_define_method(rb_cFile,"default_acl",RUBY_METHOD_FUNC(File_default_acl),0);
	rb_define_method(rb_cFile,"default_acl=",RUBY_METHOD_FUNC(File_set_default_acl),1);
	rb_define_singleton_method(rb_cFile,"get_access_acl",RUBY_METHOD_FUNC(File_single_access_acl),1);
	rb_define_singleton_method(rb_cFile,"set_access_acl",RUBY_METHOD_FUNC(File_single_set_access_acl),2);
	rb_define_singleton_method(rb_cFile,"get_default_acl",RUBY_METHOD_FUNC(File_single_default_acl),1);
	rb_define_singleton_method(rb_cFile,"set_default_acl",RUBY_METHOD_FUNC(File_single_set_default_acl),2);
	rb_define_method(rb_cAcl,"size",RUBY_METHOD_FUNC(ACL_size),0);
	rb_define_method(rb_cAcl,"[]",RUBY_METHOD_FUNC(ACL_get),1);
	
	rb_define_method(rb_cAcl,"delete_if",RUBY_METHOD_FUNC(ACL_delete_if),0);
	//rb_define_method(rb_cAcl,"inspect",RUBY_METHOD_FUNC(ACL_inspect),0);
	rb_define_method(rb_cAcl,"valid?",RUBY_METHOD_FUNC(ACL_valid),0);
	rb_define_method(rb_cAcl,"each",RUBY_METHOD_FUNC(ACL_entries),0);
	rb_define_method(rb_cAcl,"<<",RUBY_METHOD_FUNC(ACL_add),1);
	rb_include_module(rb_cAcl,rb_mEnumerable);
	Init_aclEntry(rb_cAcl);
}
