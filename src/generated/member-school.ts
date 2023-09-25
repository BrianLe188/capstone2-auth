import type * as grpc from '@grpc/grpc-js';
import type { MessageTypeDefinition } from '@grpc/proto-loader';


type SubtypeConstructor<Constructor extends new (...args: any) => any, Subtype> = {
  new(...args: ConstructorParameters<Constructor>): Subtype;
};

export interface ProtoGrpcType {
  member_school: {
    MemberSchool: MessageTypeDefinition
    MemberSchoolResponse: MessageTypeDefinition
    MemberSchools: MessageTypeDefinition
    MemberSchoolsResponse: MessageTypeDefinition
    UpdateMemberSchool: MessageTypeDefinition
  }
}

