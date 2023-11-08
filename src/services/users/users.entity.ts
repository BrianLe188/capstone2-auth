import {
  Column,
  Entity,
  ManyToOne,
  OneToOne,
  PrimaryGeneratedColumn,
} from "typeorm";
import { Token } from "../tokens/tokens.entity";
import { Role } from "../roles/roles.entity";

@Entity({ name: "users" })
export class User {
  @PrimaryGeneratedColumn("uuid")
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ type: "text" })
  password: string;

  @Column({ length: 30 })
  fullName: string;

  @OneToOne(() => Token, (token) => token.user)
  token: Token;

  @ManyToOne(() => Role, (role) => role.users)
  role: Role;

  @Column({ nullable: true })
  socket: string;

  @Column({ nullable: true })
  ip: string;

  @Column({ default: 0 })
  score: number;

  @Column({ default: 0 })
  ratingTime: number;
}
