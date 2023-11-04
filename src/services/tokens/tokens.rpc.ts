import { verify } from "../../utils/jwt";

const VerifyToken = async (call: any, callback: any) => {
  try {
    const { token } = call.request;
    if (token) {
      const decoded = verify(token);
      callback(null, { data: decoded });
    }
  } catch (error) {
    callback(null, { error });
  }
};

const tokenRPC = {
  VerifyToken,
};

export default tokenRPC;
