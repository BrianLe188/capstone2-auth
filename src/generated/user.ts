import type * as grpc from '@grpc/grpc-js';
import type { MessageTypeDefinition } from '@grpc/proto-loader';


type SubtypeConstructor<Constructor extends new (...args: any) => any, Subtype> = {
  new(...args: ConstructorParameters<Constructor>): Subtype;
};

export interface ProtoGrpcType {
  role: {
    Role: MessageTypeDefinition
    RoleResponse: MessageTypeDefinition
    UpdateRole: MessageTypeDefinition
  }
  user: {
    Email: MessageTypeDefinition
    Login: MessageTypeDefinition
    UpdateUser: MessageTypeDefinition
    User: MessageTypeDefinition
    UserResponse: MessageTypeDefinition
    Users: MessageTypeDefinition
    UsersResponse: MessageTypeDefinition
  }
}

