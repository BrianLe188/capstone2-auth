// Original file: admission/subject-block.proto

import type { SubjectBlock as _subject_block_SubjectBlock, SubjectBlock__Output as _subject_block_SubjectBlock__Output } from '../subject_block/SubjectBlock';

export interface SubjectBlockResponse {
  'block'?: (_subject_block_SubjectBlock | null);
  'error'?: (string);
  'response'?: "block"|"error";
}

export interface SubjectBlockResponse__Output {
  'block'?: (_subject_block_SubjectBlock__Output | null);
  'error'?: (string);
  'response': "block"|"error";
}
