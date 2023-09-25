import { AuthDB } from "../../data-source";
import { Role } from "./roles.entity";

const roleRepo = AuthDB.getRepository(Role);

const CreateRole = async (call: any, callback: any) => {
  try {
    const role: any = new Role();
    Object.keys(call.request).forEach((item) => {
      role[item] = call.request[item];
    });
    await roleRepo.save(role);
    callback(null, { role });
  } catch (error) {
    callback(null, { error });
  }
};

const UpdateRole = async (call: any, callback: any) => {
  try {
    const { id, body } = call.request;
    const updatedRole: any = await roleRepo.findOneBy({
      id,
    });
    if (updatedRole) {
      Object.keys(body).forEach((item) => {
        updatedRole[item] = body[item];
      });
      await roleRepo.save(updatedRole);
      callback(null, { role: updatedRole });
    } else {
    }
  } catch (error) {
    callback(null, { error });
  }
};

const DeleteUser = async (call: any, callback: any) => {
  try {
    const { id } = call.request;
    const role = await roleRepo.findOneBy({ id });
    if (role) {
      await roleRepo.remove(role);
      callback(null, { message: "Success" });
    } else {
      callback(null, { message: "Not found" });
    }
  } catch (error) {
    callback(null, { error });
  }
};

const roleRPC = {
  CreateRole,
  UpdateRole,
  DeleteUser,
};

export default roleRPC;
