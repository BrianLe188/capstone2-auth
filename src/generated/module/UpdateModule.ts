// Original file: admission/module.proto

import type { Module as _module_Module, Module__Output as _module_Module__Output } from '../module/Module';

export interface UpdateModule {
  'id'?: (string);
  'body'?: (_module_Module | null);
}

export interface UpdateModule__Output {
  'id': (string);
  'body': (_module_Module__Output | null);
}
