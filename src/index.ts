import dotenv from "dotenv";
dotenv.config();
import { loadSync } from "@grpc/proto-loader";
import { PROTO_PATH } from "./protos";
import {
  Server,
  ServerCredentials,
  loadPackageDefinition,
} from "@grpc/grpc-js";
import { ProtoGrpcType } from "./generated/auth";
import { AuthDB } from "./data-source";
import userRPC from "./services/users/users.rpc";
import roleRPC from "./services/roles/roles.rpc";

const packageDefinition = loadSync(PROTO_PATH);

const service = loadPackageDefinition(
  packageDefinition
) as unknown as ProtoGrpcType;

function main() {
  const server = new Server();
  server.addService(service.auth.Auth.service, {
    ...userRPC,
    ...roleRPC,
  });
  if (process.env.AUTH_GRPC) {
    server.bindAsync(
      process.env.AUTH_GRPC,
      ServerCredentials.createInsecure(),
      () => {
        server.start();
        console.log(`Auth is running on ${process.env.AUTH_GRPC}`);
        AuthDB.initialize()
          .then(() => {
            console.log(`Auth database available`);
          })
          .catch((error) => {
            console.log(error);
          });
      }
    );
  }
}

main();
