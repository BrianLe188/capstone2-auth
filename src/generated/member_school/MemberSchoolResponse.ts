// Original file: admission/member-school.proto

import type { MemberSchool as _member_school_MemberSchool, MemberSchool__Output as _member_school_MemberSchool__Output } from '../member_school/MemberSchool';

export interface MemberSchoolResponse {
  'school'?: (_member_school_MemberSchool | null);
  'error'?: (string);
  'resopnse'?: "school"|"error";
}

export interface MemberSchoolResponse__Output {
  'school'?: (_member_school_MemberSchool__Output | null);
  'error'?: (string);
  'resopnse': "school"|"error";
}
