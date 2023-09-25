// Original file: admission/member-school.proto

import type { MemberSchools as _member_school_MemberSchools, MemberSchools__Output as _member_school_MemberSchools__Output } from '../member_school/MemberSchools';

export interface MemberSchoolsResponse {
  'schools'?: (_member_school_MemberSchools | null);
  'error'?: (string);
  'response'?: "schools"|"error";
}

export interface MemberSchoolsResponse__Output {
  'schools'?: (_member_school_MemberSchools__Output | null);
  'error'?: (string);
  'response': "schools"|"error";
}
