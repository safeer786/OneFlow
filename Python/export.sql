--------------------------------------------------------
--  File created - Sunday-September-10-2017   
--------------------------------------------------------
--------------------------------------------------------
--  DDL for Table TEST
--------------------------------------------------------

  CREATE TABLE "SYSTEM"."TEST" 
   (	"ID" NUMBER(*,0), 
	"NAME" VARCHAR2(20 BYTE)
   ) PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 NOCOMPRESS LOGGING
  STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 MAXEXTENTS 2147483645
  PCTINCREASE 0 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT FLASH_CACHE DEFAULT CELL_FLASH_CACHE DEFAULT)
  TABLESPACE "SYSTEM" ;
REM INSERTING into SYSTEM.TEST
SET DEFINE OFF;
Insert into SYSTEM.TEST (ID,NAME) values ('1','sam');
Insert into SYSTEM.TEST (ID,NAME) values ('2','bhai');
