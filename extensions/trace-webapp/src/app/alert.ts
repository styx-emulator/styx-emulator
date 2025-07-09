// SPDX-License-Identifier: BSD-2-Clause
import { AppRpcError } from "./error.service";

type AlertTargetType = object | string | Error;

export class Alert {
  type: string;
  message: AlertTargetType;

  constructor(type: string, message: AlertTargetType) {
    this.type = type;
    if (message instanceof AppRpcError) {
      this.message = <Error>message;
    } else if (message instanceof String) {
      this.message = message;
    } else {
      this.message = message as Error;
    }
  }
}

export class ErrorAlert extends Alert {
  constructor(msg: AlertTargetType) {
    super("danger", msg);
  }
}

export class InfoAlert extends Alert {
  constructor(msg: AlertTargetType) {
    super("info", msg);
  }
}

export const ALERT_OK = new Alert("success", "item");
