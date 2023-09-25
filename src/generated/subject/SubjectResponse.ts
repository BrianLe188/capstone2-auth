// Original file: admission/subject.proto

import type { Subject as _subject_Subject, Subject__Output as _subject_Subject__Output } from '../subject/Subject';

export interface SubjectResponse {
  'subject'?: (_subject_Subject | null);
  'error'?: (string);
  'response'?: "subject"|"error";
}

export interface SubjectResponse__Output {
  'subject'?: (_subject_Subject__Output | null);
  'error'?: (string);
  'response': "subject"|"error";
}
