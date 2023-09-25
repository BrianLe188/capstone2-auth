// Original file: admission/majors.proto

import type { Majors as _majors_Majors, Majors__Output as _majors_Majors__Output } from '../majors/Majors';

export interface MajorsResponse {
  'major'?: (_majors_Majors | null);
  'error'?: (string);
  'response'?: "major"|"error";
}

export interface MajorsResponse__Output {
  'major'?: (_majors_Majors__Output | null);
  'error'?: (string);
  'response': "major"|"error";
}
