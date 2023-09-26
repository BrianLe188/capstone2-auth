// Original file: auth/user.proto

import type { Role as _role_Role, Role__Output as _role_Role__Output } from '../role/Role';

export interface User {
  'id'?: (string);
  'email'?: (string);
  'password'?: (string);
  'fullName'?: (string);
  'role'?: (_role_Role | null);
  '_id'?: "id";
  '_role'?: "role";
}

export interface User__Output {
  'id'?: (string);
  'email': (string);
  'password': (string);
  'fullName': (string);
  'role'?: (_role_Role__Output | null);
  '_id': "id";
  '_role': "role";
}
