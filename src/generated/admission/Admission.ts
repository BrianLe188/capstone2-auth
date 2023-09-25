// Original file: admission/admission.proto

import type * as grpc from '@grpc/grpc-js'
import type { MethodDefinition } from '@grpc/proto-loader'
import type { GreetRequest as _admission_GreetRequest, GreetRequest__Output as _admission_GreetRequest__Output } from '../admission/GreetRequest';
import type { GreetResponse as _admission_GreetResponse, GreetResponse__Output as _admission_GreetResponse__Output } from '../admission/GreetResponse';
import type { Majors as _majors_Majors, Majors__Output as _majors_Majors__Output } from '../majors/Majors';
import type { MajorsResponse as _majors_MajorsResponse, MajorsResponse__Output as _majors_MajorsResponse__Output } from '../majors/MajorsResponse';
import type { MemberSchool as _member_school_MemberSchool, MemberSchool__Output as _member_school_MemberSchool__Output } from '../member_school/MemberSchool';
import type { MemberSchoolResponse as _member_school_MemberSchoolResponse, MemberSchoolResponse__Output as _member_school_MemberSchoolResponse__Output } from '../member_school/MemberSchoolResponse';
import type { MemberSchoolsResponse as _member_school_MemberSchoolsResponse, MemberSchoolsResponse__Output as _member_school_MemberSchoolsResponse__Output } from '../member_school/MemberSchoolsResponse';
import type { Message as _admission_Message, Message__Output as _admission_Message__Output } from '../admission/Message';
import type { Module as _module_Module, Module__Output as _module_Module__Output } from '../module/Module';
import type { ModuleResponse as _module_ModuleResponse, ModuleResponse__Output as _module_ModuleResponse__Output } from '../module/ModuleResponse';
import type { ModulesResponse as _module_ModulesResponse, ModulesResponse__Output as _module_ModulesResponse__Output } from '../module/ModulesResponse';
import type { RequestEmpty as _admission_RequestEmpty, RequestEmpty__Output as _admission_RequestEmpty__Output } from '../admission/RequestEmpty';
import type { Subject as _subject_Subject, Subject__Output as _subject_Subject__Output } from '../subject/Subject';
import type { SubjectBlock as _subject_block_SubjectBlock, SubjectBlock__Output as _subject_block_SubjectBlock__Output } from '../subject_block/SubjectBlock';
import type { SubjectBlockResponse as _subject_block_SubjectBlockResponse, SubjectBlockResponse__Output as _subject_block_SubjectBlockResponse__Output } from '../subject_block/SubjectBlockResponse';
import type { SubjectResponse as _subject_SubjectResponse, SubjectResponse__Output as _subject_SubjectResponse__Output } from '../subject/SubjectResponse';
import type { Target as _admission_Target, Target__Output as _admission_Target__Output } from '../admission/Target';
import type { UpdateMajors as _majors_UpdateMajors, UpdateMajors__Output as _majors_UpdateMajors__Output } from '../majors/UpdateMajors';
import type { UpdateMemberSchool as _member_school_UpdateMemberSchool, UpdateMemberSchool__Output as _member_school_UpdateMemberSchool__Output } from '../member_school/UpdateMemberSchool';
import type { UpdateModule as _module_UpdateModule, UpdateModule__Output as _module_UpdateModule__Output } from '../module/UpdateModule';
import type { UpdateSubject as _subject_UpdateSubject, UpdateSubject__Output as _subject_UpdateSubject__Output } from '../subject/UpdateSubject';
import type { UpdateSubjectBlock as _subject_block_UpdateSubjectBlock, UpdateSubjectBlock__Output as _subject_block_UpdateSubjectBlock__Output } from '../subject_block/UpdateSubjectBlock';

export interface AdmissionClient extends grpc.Client {
  CreateMajor(argument: _majors_Majors, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  CreateMajor(argument: _majors_Majors, metadata: grpc.Metadata, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  CreateMajor(argument: _majors_Majors, options: grpc.CallOptions, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  CreateMajor(argument: _majors_Majors, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  createMajor(argument: _majors_Majors, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  createMajor(argument: _majors_Majors, metadata: grpc.Metadata, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  createMajor(argument: _majors_Majors, options: grpc.CallOptions, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  createMajor(argument: _majors_Majors, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  
  CreateMemberSchool(argument: _member_school_MemberSchool, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  CreateMemberSchool(argument: _member_school_MemberSchool, metadata: grpc.Metadata, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  CreateMemberSchool(argument: _member_school_MemberSchool, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  CreateMemberSchool(argument: _member_school_MemberSchool, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  createMemberSchool(argument: _member_school_MemberSchool, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  createMemberSchool(argument: _member_school_MemberSchool, metadata: grpc.Metadata, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  createMemberSchool(argument: _member_school_MemberSchool, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  createMemberSchool(argument: _member_school_MemberSchool, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  
  CreateModule(argument: _module_Module, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  CreateModule(argument: _module_Module, metadata: grpc.Metadata, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  CreateModule(argument: _module_Module, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  CreateModule(argument: _module_Module, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  createModule(argument: _module_Module, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  createModule(argument: _module_Module, metadata: grpc.Metadata, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  createModule(argument: _module_Module, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  createModule(argument: _module_Module, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  
  CreateSubject(argument: _subject_Subject, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  CreateSubject(argument: _subject_Subject, metadata: grpc.Metadata, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  CreateSubject(argument: _subject_Subject, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  CreateSubject(argument: _subject_Subject, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  createSubject(argument: _subject_Subject, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  createSubject(argument: _subject_Subject, metadata: grpc.Metadata, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  createSubject(argument: _subject_Subject, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  createSubject(argument: _subject_Subject, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  
  CreateSubjectBlock(argument: _subject_block_SubjectBlock, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  CreateSubjectBlock(argument: _subject_block_SubjectBlock, metadata: grpc.Metadata, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  CreateSubjectBlock(argument: _subject_block_SubjectBlock, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  CreateSubjectBlock(argument: _subject_block_SubjectBlock, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  createSubjectBlock(argument: _subject_block_SubjectBlock, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  createSubjectBlock(argument: _subject_block_SubjectBlock, metadata: grpc.Metadata, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  createSubjectBlock(argument: _subject_block_SubjectBlock, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  createSubjectBlock(argument: _subject_block_SubjectBlock, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  
  Default(argument: _admission_GreetRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_GreetResponse__Output>): grpc.ClientUnaryCall;
  Default(argument: _admission_GreetRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_GreetResponse__Output>): grpc.ClientUnaryCall;
  Default(argument: _admission_GreetRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_GreetResponse__Output>): grpc.ClientUnaryCall;
  Default(argument: _admission_GreetRequest, callback: grpc.requestCallback<_admission_GreetResponse__Output>): grpc.ClientUnaryCall;
  default(argument: _admission_GreetRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_GreetResponse__Output>): grpc.ClientUnaryCall;
  default(argument: _admission_GreetRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_GreetResponse__Output>): grpc.ClientUnaryCall;
  default(argument: _admission_GreetRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_GreetResponse__Output>): grpc.ClientUnaryCall;
  default(argument: _admission_GreetRequest, callback: grpc.requestCallback<_admission_GreetResponse__Output>): grpc.ClientUnaryCall;
  
  DeleteMajor(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteMajor(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteMajor(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteMajor(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteMajor(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteMajor(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteMajor(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteMajor(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  
  DeleteMemberSchool(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteMemberSchool(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteMemberSchool(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteMemberSchool(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteMemberSchool(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteMemberSchool(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteMemberSchool(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteMemberSchool(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  
  DeleteModule(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteModule(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteModule(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteModule(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteModule(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteModule(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteModule(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteModule(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  
  DeleteSubject(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteSubject(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteSubject(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteSubject(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteSubject(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteSubject(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteSubject(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteSubject(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  
  DeleteSubjectBlock(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteSubjectBlock(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteSubjectBlock(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  DeleteSubjectBlock(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteSubjectBlock(argument: _admission_Target, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteSubjectBlock(argument: _admission_Target, metadata: grpc.Metadata, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteSubjectBlock(argument: _admission_Target, options: grpc.CallOptions, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  deleteSubjectBlock(argument: _admission_Target, callback: grpc.requestCallback<_admission_Message__Output>): grpc.ClientUnaryCall;
  
  GetAllMemberSchool(argument: _admission_RequestEmpty, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolsResponse__Output>): grpc.ClientUnaryCall;
  GetAllMemberSchool(argument: _admission_RequestEmpty, metadata: grpc.Metadata, callback: grpc.requestCallback<_member_school_MemberSchoolsResponse__Output>): grpc.ClientUnaryCall;
  GetAllMemberSchool(argument: _admission_RequestEmpty, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolsResponse__Output>): grpc.ClientUnaryCall;
  GetAllMemberSchool(argument: _admission_RequestEmpty, callback: grpc.requestCallback<_member_school_MemberSchoolsResponse__Output>): grpc.ClientUnaryCall;
  getAllMemberSchool(argument: _admission_RequestEmpty, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolsResponse__Output>): grpc.ClientUnaryCall;
  getAllMemberSchool(argument: _admission_RequestEmpty, metadata: grpc.Metadata, callback: grpc.requestCallback<_member_school_MemberSchoolsResponse__Output>): grpc.ClientUnaryCall;
  getAllMemberSchool(argument: _admission_RequestEmpty, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolsResponse__Output>): grpc.ClientUnaryCall;
  getAllMemberSchool(argument: _admission_RequestEmpty, callback: grpc.requestCallback<_member_school_MemberSchoolsResponse__Output>): grpc.ClientUnaryCall;
  
  GetAllModule(argument: _admission_RequestEmpty, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModulesResponse__Output>): grpc.ClientUnaryCall;
  GetAllModule(argument: _admission_RequestEmpty, metadata: grpc.Metadata, callback: grpc.requestCallback<_module_ModulesResponse__Output>): grpc.ClientUnaryCall;
  GetAllModule(argument: _admission_RequestEmpty, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModulesResponse__Output>): grpc.ClientUnaryCall;
  GetAllModule(argument: _admission_RequestEmpty, callback: grpc.requestCallback<_module_ModulesResponse__Output>): grpc.ClientUnaryCall;
  getAllModule(argument: _admission_RequestEmpty, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModulesResponse__Output>): grpc.ClientUnaryCall;
  getAllModule(argument: _admission_RequestEmpty, metadata: grpc.Metadata, callback: grpc.requestCallback<_module_ModulesResponse__Output>): grpc.ClientUnaryCall;
  getAllModule(argument: _admission_RequestEmpty, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModulesResponse__Output>): grpc.ClientUnaryCall;
  getAllModule(argument: _admission_RequestEmpty, callback: grpc.requestCallback<_module_ModulesResponse__Output>): grpc.ClientUnaryCall;
  
  UpdateMajor(argument: _majors_UpdateMajors, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  UpdateMajor(argument: _majors_UpdateMajors, metadata: grpc.Metadata, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  UpdateMajor(argument: _majors_UpdateMajors, options: grpc.CallOptions, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  UpdateMajor(argument: _majors_UpdateMajors, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  updateMajor(argument: _majors_UpdateMajors, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  updateMajor(argument: _majors_UpdateMajors, metadata: grpc.Metadata, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  updateMajor(argument: _majors_UpdateMajors, options: grpc.CallOptions, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  updateMajor(argument: _majors_UpdateMajors, callback: grpc.requestCallback<_majors_MajorsResponse__Output>): grpc.ClientUnaryCall;
  
  UpdateMemberSchool(argument: _member_school_UpdateMemberSchool, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  UpdateMemberSchool(argument: _member_school_UpdateMemberSchool, metadata: grpc.Metadata, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  UpdateMemberSchool(argument: _member_school_UpdateMemberSchool, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  UpdateMemberSchool(argument: _member_school_UpdateMemberSchool, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  updateMemberSchool(argument: _member_school_UpdateMemberSchool, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  updateMemberSchool(argument: _member_school_UpdateMemberSchool, metadata: grpc.Metadata, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  updateMemberSchool(argument: _member_school_UpdateMemberSchool, options: grpc.CallOptions, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  updateMemberSchool(argument: _member_school_UpdateMemberSchool, callback: grpc.requestCallback<_member_school_MemberSchoolResponse__Output>): grpc.ClientUnaryCall;
  
  UpdateModule(argument: _module_UpdateModule, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  UpdateModule(argument: _module_UpdateModule, metadata: grpc.Metadata, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  UpdateModule(argument: _module_UpdateModule, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  UpdateModule(argument: _module_UpdateModule, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  updateModule(argument: _module_UpdateModule, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  updateModule(argument: _module_UpdateModule, metadata: grpc.Metadata, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  updateModule(argument: _module_UpdateModule, options: grpc.CallOptions, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  updateModule(argument: _module_UpdateModule, callback: grpc.requestCallback<_module_ModuleResponse__Output>): grpc.ClientUnaryCall;
  
  UpdateSubject(argument: _subject_UpdateSubject, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  UpdateSubject(argument: _subject_UpdateSubject, metadata: grpc.Metadata, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  UpdateSubject(argument: _subject_UpdateSubject, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  UpdateSubject(argument: _subject_UpdateSubject, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  updateSubject(argument: _subject_UpdateSubject, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  updateSubject(argument: _subject_UpdateSubject, metadata: grpc.Metadata, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  updateSubject(argument: _subject_UpdateSubject, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  updateSubject(argument: _subject_UpdateSubject, callback: grpc.requestCallback<_subject_SubjectResponse__Output>): grpc.ClientUnaryCall;
  
  UpdateSubjectBlock(argument: _subject_block_UpdateSubjectBlock, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  UpdateSubjectBlock(argument: _subject_block_UpdateSubjectBlock, metadata: grpc.Metadata, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  UpdateSubjectBlock(argument: _subject_block_UpdateSubjectBlock, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  UpdateSubjectBlock(argument: _subject_block_UpdateSubjectBlock, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  updateSubjectBlock(argument: _subject_block_UpdateSubjectBlock, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  updateSubjectBlock(argument: _subject_block_UpdateSubjectBlock, metadata: grpc.Metadata, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  updateSubjectBlock(argument: _subject_block_UpdateSubjectBlock, options: grpc.CallOptions, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  updateSubjectBlock(argument: _subject_block_UpdateSubjectBlock, callback: grpc.requestCallback<_subject_block_SubjectBlockResponse__Output>): grpc.ClientUnaryCall;
  
}

export interface AdmissionHandlers extends grpc.UntypedServiceImplementation {
  CreateMajor: grpc.handleUnaryCall<_majors_Majors__Output, _majors_MajorsResponse>;
  
  CreateMemberSchool: grpc.handleUnaryCall<_member_school_MemberSchool__Output, _member_school_MemberSchoolResponse>;
  
  CreateModule: grpc.handleUnaryCall<_module_Module__Output, _module_ModuleResponse>;
  
  CreateSubject: grpc.handleUnaryCall<_subject_Subject__Output, _subject_SubjectResponse>;
  
  CreateSubjectBlock: grpc.handleUnaryCall<_subject_block_SubjectBlock__Output, _subject_block_SubjectBlockResponse>;
  
  Default: grpc.handleUnaryCall<_admission_GreetRequest__Output, _admission_GreetResponse>;
  
  DeleteMajor: grpc.handleUnaryCall<_admission_Target__Output, _admission_Message>;
  
  DeleteMemberSchool: grpc.handleUnaryCall<_admission_Target__Output, _admission_Message>;
  
  DeleteModule: grpc.handleUnaryCall<_admission_Target__Output, _admission_Message>;
  
  DeleteSubject: grpc.handleUnaryCall<_admission_Target__Output, _admission_Message>;
  
  DeleteSubjectBlock: grpc.handleUnaryCall<_admission_Target__Output, _admission_Message>;
  
  GetAllMemberSchool: grpc.handleUnaryCall<_admission_RequestEmpty__Output, _member_school_MemberSchoolsResponse>;
  
  GetAllModule: grpc.handleUnaryCall<_admission_RequestEmpty__Output, _module_ModulesResponse>;
  
  UpdateMajor: grpc.handleUnaryCall<_majors_UpdateMajors__Output, _majors_MajorsResponse>;
  
  UpdateMemberSchool: grpc.handleUnaryCall<_member_school_UpdateMemberSchool__Output, _member_school_MemberSchoolResponse>;
  
  UpdateModule: grpc.handleUnaryCall<_module_UpdateModule__Output, _module_ModuleResponse>;
  
  UpdateSubject: grpc.handleUnaryCall<_subject_UpdateSubject__Output, _subject_SubjectResponse>;
  
  UpdateSubjectBlock: grpc.handleUnaryCall<_subject_block_UpdateSubjectBlock__Output, _subject_block_SubjectBlockResponse>;
  
}

export interface AdmissionDefinition extends grpc.ServiceDefinition {
  CreateMajor: MethodDefinition<_majors_Majors, _majors_MajorsResponse, _majors_Majors__Output, _majors_MajorsResponse__Output>
  CreateMemberSchool: MethodDefinition<_member_school_MemberSchool, _member_school_MemberSchoolResponse, _member_school_MemberSchool__Output, _member_school_MemberSchoolResponse__Output>
  CreateModule: MethodDefinition<_module_Module, _module_ModuleResponse, _module_Module__Output, _module_ModuleResponse__Output>
  CreateSubject: MethodDefinition<_subject_Subject, _subject_SubjectResponse, _subject_Subject__Output, _subject_SubjectResponse__Output>
  CreateSubjectBlock: MethodDefinition<_subject_block_SubjectBlock, _subject_block_SubjectBlockResponse, _subject_block_SubjectBlock__Output, _subject_block_SubjectBlockResponse__Output>
  Default: MethodDefinition<_admission_GreetRequest, _admission_GreetResponse, _admission_GreetRequest__Output, _admission_GreetResponse__Output>
  DeleteMajor: MethodDefinition<_admission_Target, _admission_Message, _admission_Target__Output, _admission_Message__Output>
  DeleteMemberSchool: MethodDefinition<_admission_Target, _admission_Message, _admission_Target__Output, _admission_Message__Output>
  DeleteModule: MethodDefinition<_admission_Target, _admission_Message, _admission_Target__Output, _admission_Message__Output>
  DeleteSubject: MethodDefinition<_admission_Target, _admission_Message, _admission_Target__Output, _admission_Message__Output>
  DeleteSubjectBlock: MethodDefinition<_admission_Target, _admission_Message, _admission_Target__Output, _admission_Message__Output>
  GetAllMemberSchool: MethodDefinition<_admission_RequestEmpty, _member_school_MemberSchoolsResponse, _admission_RequestEmpty__Output, _member_school_MemberSchoolsResponse__Output>
  GetAllModule: MethodDefinition<_admission_RequestEmpty, _module_ModulesResponse, _admission_RequestEmpty__Output, _module_ModulesResponse__Output>
  UpdateMajor: MethodDefinition<_majors_UpdateMajors, _majors_MajorsResponse, _majors_UpdateMajors__Output, _majors_MajorsResponse__Output>
  UpdateMemberSchool: MethodDefinition<_member_school_UpdateMemberSchool, _member_school_MemberSchoolResponse, _member_school_UpdateMemberSchool__Output, _member_school_MemberSchoolResponse__Output>
  UpdateModule: MethodDefinition<_module_UpdateModule, _module_ModuleResponse, _module_UpdateModule__Output, _module_ModuleResponse__Output>
  UpdateSubject: MethodDefinition<_subject_UpdateSubject, _subject_SubjectResponse, _subject_UpdateSubject__Output, _subject_SubjectResponse__Output>
  UpdateSubjectBlock: MethodDefinition<_subject_block_UpdateSubjectBlock, _subject_block_SubjectBlockResponse, _subject_block_UpdateSubjectBlock__Output, _subject_block_SubjectBlockResponse__Output>
}
