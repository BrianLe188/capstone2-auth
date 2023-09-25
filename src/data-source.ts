import { DataSource, DataSourceOptions } from "typeorm";
import { User } from "./services/users/users.entity";
import { Token } from "./services/tokens/tokens.entity";
import { Role } from "./services/roles/roles.entity";

export const AuthDB = new DataSource({
  type: process.env.DB_TYPE,
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  username: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  synchronize: true,
  logging: true,
  entities: [User, Token, Role],
  subscribers: [],
  migrations: [],
} as DataSourceOptions);
