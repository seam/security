insert into IdentityObjectType(id, name) values (1, 'USER');
insert into IdentityObjectType(id, name) values (2, 'GROUP');

insert into IdentityObject (id, name, identity_object_type_id) values (1, 'shane', 1);
insert into IdentityObject (id, name, identity_object_type_id) values (2, 'demo', 1);
insert into IdentityObject (id, name, identity_object_type_id) values (3, 'Head Office', 2);

insert into IdentityObjectCredentialType (id, name) values (1, 'PASSWORD');

insert into IdentityObjectCredential (id, identity_object_id, credential_type_id, value) values (1, 1, 1, 'password');
insert into IdentityObjectCredential (id, identity_object_id, credential_type_id, value) values (2, 2, 1, 'demo');

insert into IdentityObjectRelationshipType (id, name) values (1, 'MEMBER_OF');
insert into IdentityObjectRelationshipType (id, name) values (2, 'ROLE');

insert into IdentityObjectRelationship (id, name, relationship_type_id, identity_from_id, identity_to_id) values (1, 'admin', 2, 1, 3);
