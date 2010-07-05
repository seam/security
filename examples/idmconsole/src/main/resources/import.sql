insert into IdentityObjectType(id, name) values (1, 'USER');
insert into IdentityObjectType(id, name) values (2, 'GROUP');

insert into IdentityObject (id, name, identity_object_type_id) values (1, 'shane', 1);
insert into IdentityObject (id, name, identity_object_type_id) values (2, 'demo', 1);

insert into IdentityObjectCredentialType (id, name) values (1, 'PASSWORD');

insert into IdentityObjectCredential (id, identity_object_id, credential_type_id, value) values (1, 1, 1, 'password');
insert into IdentityObjectCredential (id, identity_object_id, credential_type_id, value) values (2, 2, 1, 'demo');

