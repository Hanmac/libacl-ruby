#include "main.hpp"
#define _self wrap<acl_entry_t>(self)

VALUE ACLEntry_set_perm(VALUE self,VALUE perm);
VALUE ACLEntry_set_id(VALUE self,VALUE id);

VALUE ACLEntry_alloc(VALUE self)
{
	acl_t acl = acl_init(1);
	acl_entry_t entry;
	acl_create_entry(&acl,&entry);
	acl_free(acl);
	return wrap(entry);
}

VALUE ACLEntry_initialize_copy(VALUE self, VALUE other)
{
	rb_call_super(1,&other);
	acl_copy_entry(_self,wrap<acl_entry_t>(other));
	return self;
}

VALUE ACLEntry_initialize(int argc, VALUE *argv,VALUE self)
{
	VALUE type,perm,id;
	rb_scan_args(argc, argv, "21", &type,&perm,&id);
	type = rb_funcall(type,rb_intern("to_sym"),0);
	if(SYM2ID(type) == rb_intern("user")){
		if(NIL_P(id))
			acl_set_tag_type(_self,ACL_USER_OBJ);
		else
			acl_set_tag_type(_self,ACL_USER);
	}else if(SYM2ID(type) == rb_intern("group")){
		if(NIL_P(id))
			acl_set_tag_type(_self,ACL_GROUP_OBJ);
		else
			acl_set_tag_type(_self,ACL_GROUP);
	}else if(SYM2ID(type) == rb_intern("other")){
			acl_set_tag_type(_self,ACL_OTHER);
	}else if(SYM2ID(type) == rb_intern("mask")){
			acl_set_tag_type(_self,ACL_MASK);
	}else
		rb_raise(rb_eTypeError,"exepted one of :user,:group,:other,:mask!");
	ACLEntry_set_perm(self,perm);
	if(!NIL_P(id))
		ACLEntry_set_id(self,id);
	return self;
}

VALUE ACLEntry_id(VALUE self)
{
	int* id = (int*) acl_get_qualifier(_self);
return id==NULL ? Qnil : INT2NUM(*id);
}

VALUE ACLEntry_id_name(VALUE self)
{
	acl_tag_t tag;
	acl_get_tag_type(_self,&tag);
	int* id = (int*) acl_get_qualifier(_self);
	passwd* pwd;
	group* grp;
	VALUE result = Qnil;
	switch(tag){
	case ACL_USER:
		pwd = getpwuid(*id);
		if(pwd)
			result = rb_str_new2(pwd->pw_name);
		break;
	case ACL_GROUP:
		grp = getgrgid(*id);
		if(grp)
			result = rb_str_new2(grp->gr_name);
		break;
	}
	return result;
}

VALUE ACLEntry_set_id(VALUE self,VALUE id)
{
	acl_tag_t tag;
	acl_get_tag_type(_self,&tag);
	if(NIL_P(id)){
		switch(tag){
		case ACL_USER:
			acl_set_tag_type(_self,ACL_USER_OBJ);
			break;
		case ACL_GROUP:
			acl_set_tag_type(_self,ACL_GROUP_OBJ);
			break;
		}
		acl_set_qualifier(_self,NULL);
	}else if(rb_obj_is_kind_of(id,rb_cInteger)){
		int i;
		switch(tag){
		case ACL_USER_OBJ:
		case ACL_USER:
		case ACL_GROUP_OBJ:
		case ACL_GROUP:
			i = NUM2INT(id);
			acl_set_qualifier(_self,&i);
		default:
			rb_raise(rb_eArgError,"id only supported with user or group.");
		}
	}else{
		passwd* pwd;
		group* grp;
		id= rb_funcall(id,rb_intern("to_s"),0);
		const char* name = rb_string_value_cstr(&id);
		switch(tag){
		case ACL_USER_OBJ:
		case ACL_USER:
			pwd = getpwnam(name);
			if(pwd){
				uid_t u = pwd->pw_uid;
				acl_set_tag_type(_self,ACL_USER);
				acl_set_qualifier(_self,&u);
			}else
				rb_raise(rb_eArgError,"There is no User with the name:%s!",name);
			break;
		case ACL_GROUP_OBJ:
		case ACL_GROUP:
			grp = getgrnam(name);
			if(grp){
					gid_t g = grp->gr_gid;
					acl_set_tag_type(_self,ACL_GROUP);
					acl_set_qualifier(_self,&g);
			}else
				rb_raise(rb_eArgError,"There is no Group with the name:%s!",name);
			break;
		default:
			rb_raise(rb_eArgError,"id only supported with user or group.");
		}
	}
	return id;
}
VALUE ACLEntry_perm(VALUE self)
{
	acl_permset_t set;
	acl_get_permset(_self,&set);	
	char perm[3];
	perm[0] = acl_get_perm(set,ACL_READ) ? 'r' : '-';
	perm[1] = acl_get_perm(set,ACL_WRITE) ? 'w' : '-';
	perm[2] = acl_get_perm(set,ACL_EXECUTE) ? 'x' : '-';
	return rb_str_new(perm,3);
}

VALUE ACLEntry_set_perm(VALUE self,VALUE perm)
{
	acl_permset_t set;
	acl_get_permset(_self,&set);
	acl_clear_perms(set);
	if(rb_obj_is_kind_of(perm,rb_cInteger)){
		int cperm = NUM2INT(perm);
		if((cperm & ACL_READ) == ACL_READ)
			acl_add_perm(set,ACL_READ);
		if((cperm & ACL_WRITE) == ACL_WRITE)
			acl_add_perm(set,ACL_WRITE);
		if((cperm & ACL_EXECUTE) == ACL_EXECUTE)
			acl_add_perm(set,ACL_EXECUTE);
	}else{
		perm= rb_funcall(perm,rb_intern("to_s"),0);
		const char* cperm = rb_string_value_cstr(&perm);
		for(unsigned int i = 0;i<strlen(cperm);i++){
			switch(cperm[i]){
			case 'r':
				acl_add_perm(set,ACL_READ);
				break;
			case 'w':
				acl_add_perm(set,ACL_WRITE);
				break;
			case 'x':
				acl_add_perm(set,ACL_EXECUTE);
				break;
			}
		}
	}
	return perm;
}

VALUE ACLEntry_type(VALUE self)
{
	acl_tag_t tag;
	acl_get_tag_type(_self,&tag);
	return INT2NUM(tag);
}
VALUE ACLEntry_readable(VALUE self)
{
	acl_permset_t set;
	acl_get_permset(_self,&set);
	return acl_get_perm(set,ACL_READ) ? Qtrue : Qfalse;
}
VALUE ACLEntry_writeable(VALUE self)
{
	acl_permset_t set;
	acl_get_permset(_self,&set);
	return acl_get_perm(set,ACL_WRITE) ? Qtrue : Qfalse;
}
VALUE ACLEntry_executable(VALUE self)
{
	acl_permset_t set;
	acl_get_permset(_self,&set);
	return acl_get_perm(set,ACL_EXECUTE) ? Qtrue : Qfalse;
}
VALUE ACLEntry_clear(VALUE self)
{
	acl_permset_t set;
	acl_get_permset(_self,&set);
	acl_clear_perms(set);
	return self;
}

VALUE ACLEntry_to_i(VALUE self)
{
	acl_permset_t set;
	acl_get_permset(_self,&set);
	int i = 0;
	if(acl_get_perm(set,ACL_READ))
		i += ACL_READ;
	if(acl_get_perm(set,ACL_WRITE))
		i += ACL_WRITE;
	if(acl_get_perm(set,ACL_EXECUTE))
		i += ACL_EXECUTE;
	return INT2NUM(i);
}

VALUE ACLEntry_inspect(VALUE self)
{
	acl_tag_t tag;
	acl_get_tag_type(_self,&tag);
	passwd* pwd;
	group* grp;
	int* id = (int*) acl_get_qualifier(_self);
	VALUE array[4], result = Qnil;
	array[2]=array[3]=ACLEntry_perm(self);
	switch(tag){
	case ACL_MASK:
		array[0]=rb_str_new2("#<%s:Mask:%s>");
		array[1]=rb_class_of(self);	
		result = rb_f_sprintf(3,array);
		break;
	case ACL_OTHER:
		array[0]=rb_str_new2("#<%s:Other:%s>");
		array[1]=rb_class_of(self);	
		result = rb_f_sprintf(3,array);
		break;
	case ACL_USER:		
		pwd = getpwuid(*id);
		if(pwd){
			array[0]=rb_str_new2("#<%s:User(%s):%s>");
			array[2]=rb_str_new2(pwd->pw_name);
		}else{
			array[0]=rb_str_new2("#<%s:User(%d):%s>");
			array[2]=INT2NUM(*id);
		}
		array[1]=rb_class_of(self);
		result = rb_f_sprintf(4,array);
		break;
	case ACL_USER_OBJ:
		array[0]=rb_str_new2("#<%s:User:%s>");
		array[1]=rb_class_of(self);	
		result = rb_f_sprintf(3,array);
		break;
	case ACL_GROUP:
		grp = getgrgid(*id);
		if(grp){
			array[0]=rb_str_new2("#<%s:Group(%s):%s>");
			array[2]=rb_str_new2(grp->gr_name);
		}else{
			array[0]=rb_str_new2("#<%s:Group(%d):%s>");
			array[2]=INT2NUM(*id);
		}
		array[1]=rb_class_of(self);
		result = rb_f_sprintf(4,array);
		break;
	case ACL_GROUP_OBJ:
		array[0]=rb_str_new2("#<%s:Group:%s>");
		array[1]=rb_class_of(self);	
		result = rb_f_sprintf(3,array);
		break;
	}
	return result;
}

VALUE ACLEntry_set_readable(VALUE self,VALUE val){
	acl_permset_t set;
	acl_get_permset(_self,&set);
	RTEST(val) ? acl_add_perm(set,ACL_READ) : acl_delete_perm(set,ACL_READ);
	return val;
}
VALUE ACLEntry_set_writeable(VALUE self,VALUE val){
	acl_permset_t set;
	acl_get_permset(_self,&set);
	RTEST(val) ? acl_add_perm(set,ACL_WRITE) : acl_delete_perm(set,ACL_WRITE);
	return val;
}
VALUE ACLEntry_set_executable(VALUE self,VALUE val){
	acl_permset_t set;
	acl_get_permset(_self,&set);
	RTEST(val) ? acl_add_perm(set,ACL_EXECUTE) : acl_delete_perm(set,ACL_EXECUTE);
	return val;
}

VALUE ACLEntry_cmp(VALUE self,VALUE val){
	return rb_funcall(ACLEntry_to_i(self),rb_intern("<=>"),1,rb_funcall(val,rb_intern("to_i"),0));
}
void Init_aclEntry(VALUE m){
	rb_cAclEntry = rb_define_class_under(m,"Entry",rb_cObject);
	rb_define_alloc_func(rb_cAclEntry,ACLEntry_alloc);
	rb_define_private_method(rb_cAclEntry,"initialize_copy",RUBY_METHOD_FUNC(ACLEntry_initialize_copy),1);
	
	rb_define_method(rb_cAclEntry,"initialize",RUBY_METHOD_FUNC(ACLEntry_initialize),-1);
	
	rb_define_method(rb_cAclEntry,"id",RUBY_METHOD_FUNC(ACLEntry_id),0);
	rb_define_method(rb_cAclEntry,"id_name",RUBY_METHOD_FUNC(ACLEntry_id_name),0);
	rb_define_method(rb_cAclEntry,"id_name=",RUBY_METHOD_FUNC(ACLEntry_set_id),1);
	rb_define_alias(rb_cAclEntry,"id=","id_name=");
	rb_define_method(rb_cAclEntry,"perm",RUBY_METHOD_FUNC(ACLEntry_perm),0);
	rb_define_method(rb_cAclEntry,"perm=",RUBY_METHOD_FUNC(ACLEntry_set_perm),1);
	rb_define_method(rb_cAclEntry,"type",RUBY_METHOD_FUNC(ACLEntry_type),0);
	
	rb_define_method(rb_cAclEntry,"readable",RUBY_METHOD_FUNC(ACLEntry_readable),0);
	rb_define_method(rb_cAclEntry,"writeable",RUBY_METHOD_FUNC(ACLEntry_writeable),0);
	rb_define_method(rb_cAclEntry,"executable",RUBY_METHOD_FUNC(ACLEntry_executable),0);
	
	rb_define_method(rb_cAclEntry,"readable=",RUBY_METHOD_FUNC(ACLEntry_set_readable),1);
	rb_define_method(rb_cAclEntry,"writeable=",RUBY_METHOD_FUNC(ACLEntry_set_writeable),1);
	rb_define_method(rb_cAclEntry,"executable=",RUBY_METHOD_FUNC(ACLEntry_set_executable),1);
	
	rb_define_method(rb_cAclEntry,"clear",RUBY_METHOD_FUNC(ACLEntry_clear),0);
	rb_define_method(rb_cAclEntry,"to_i",RUBY_METHOD_FUNC(ACLEntry_to_i),0);

	rb_define_method(rb_cAclEntry,"inspect",RUBY_METHOD_FUNC(ACLEntry_inspect),0);
	
	rb_define_method(rb_cAclEntry,"<=>",RUBY_METHOD_FUNC(ACLEntry_cmp),1);
	rb_include_module(rb_cAclEntry,rb_mComparable);
}
