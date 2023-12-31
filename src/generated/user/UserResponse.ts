// Original file: auth/user.proto

import type { User as _user_User, User__Output as _user_User__Output } from '../user/User';

export interface UserResponse {
  'user'?: (_user_User | null);
  'error'?: (string);
  'response'?: "user"|"error";
}

export interface UserResponse__Output {
  'user'?: (_user_User__Output | null);
  'error'?: (string);
  'response': "user"|"error";
}
