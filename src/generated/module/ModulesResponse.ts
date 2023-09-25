// Original file: admission/module.proto

import type { Modules as _module_Modules, Modules__Output as _module_Modules__Output } from '../module/Modules';

export interface ModulesResponse {
  'modules'?: (_module_Modules | null);
  'error'?: (string);
  'response'?: "modules"|"error";
}

export interface ModulesResponse__Output {
  'modules'?: (_module_Modules__Output | null);
  'error'?: (string);
  'response': "modules"|"error";
}
