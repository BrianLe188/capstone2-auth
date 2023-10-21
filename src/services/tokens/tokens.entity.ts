import {
  Column,
  Entity,
  JoinColumn,
  OneToOne,
  PrimaryGeneratedColumn,
} from "typeorm";
import { User } from "../users/users.entity";

@Entity({ name: "tokens" })
export class Token {
  @PrimaryGeneratedColumn("uuid")
  id: string;

  @Column({ type: "text", nullable: true })
  accessToken: string;

  @Column({ type: "text", nullable: true })
  refreshToken: string;

  @OneToOne(() => User, (user) => user.token)
  @JoinColumn()
  user: User;
}
