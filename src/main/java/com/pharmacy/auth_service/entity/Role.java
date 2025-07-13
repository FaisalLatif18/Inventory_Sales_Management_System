package com.pharmacy.auth_service.entity;

public enum Role {
    ADMIN,
    PHARMACIST,
    VISITOR
}
//so whenever we need to add other roles we need to alter table on mysql. bcz it define table on first time data.