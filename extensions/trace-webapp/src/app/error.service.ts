// SPDX-License-Identifier: BSD-2-Clause
import { Injectable } from "@angular/core";
import { RpcError, StatusCode } from "grpc-web";

@Injectable({
  providedIn: "root"
})
export class ErrorService {
  constructor() {}
}

export class AppError extends Error {
  constructor(message: string) {
    super(message);
  }
}
export class AppRpcError extends AppError {
  rpcError: RpcError;
  serviceName: string;
  constructor(rpcError: RpcError, serviceName: string) {
    super(rpcError.message);
    this.rpcError = rpcError;
    this.serviceName = serviceName;
  }
}

export class RpcServiceError extends AppRpcError {
  constructor(rpcError: RpcError, serviceName: string) {
    super(rpcError, serviceName);
  }
}

export class ConnectServiceError extends RpcServiceError {
  constructor(rpcError: RpcError, serviceName: string) {
    super(rpcError, serviceName);
  }
}
export class CallServiceError extends RpcServiceError {
  constructor(rpcError: RpcError, serviceName: string) {
    super(rpcError, serviceName);
  }
}

export function rpcCodeAsString(code: StatusCode) {
  return `${rpcStatusCodeToString(code)}(${code})`;
}

export function rpcStatusCodeToString(code: StatusCode): string {
  // prettier-ignore
  switch (code) {
    case StatusCode.OK: return "OK";
    case StatusCode.CANCELLED:           return "CANCELLED";
    case StatusCode.UNKNOWN:             return "UNKNOWN";
    case StatusCode.INVALID_ARGUMENT:    return "INVALID_ARGUMENT";
    case StatusCode.DEADLINE_EXCEEDED:   return "DEADLINE_EXCEEDED";
    case StatusCode.NOT_FOUND:           return "NOT_FOUND";
    case StatusCode.ALREADY_EXISTS:      return "ALREADY_EXISTS";
    case StatusCode.PERMISSION_DENIED:   return "PERMISSION_DENIED";
    case StatusCode.RESOURCE_EXHAUSTED:  return "RESOURCE_EXHAUSTED";
    case StatusCode.FAILED_PRECONDITION: return "FAILED_PRECONDITION";
    case StatusCode.ABORTED:             return "ABORTED";
    case StatusCode.OUT_OF_RANGE:        return "OUT_OF_RANGE";
    case StatusCode.UNIMPLEMENTED:       return "UNIMPLEMENTED";
    case StatusCode.INTERNAL:            return "INTERNAL";
    case StatusCode.UNAVAILABLE:         return "UNAVAILABLE";
    case StatusCode.DATA_LOSS:           return "DATA_LOSS";
    case StatusCode.UNAUTHENTICATED:     return "UNAUTHENTICATED";
  }
}

export function filterError(e: Error, svcName: string): Error {
  if (e instanceof ConnectServiceError) {
    return e;
  } else if (e instanceof RpcError) {
    const rpcError = <RpcError>e;
    switch (rpcError.code) {
      case StatusCode.UNAVAILABLE:
        return new ConnectServiceError(e, svcName);
      case StatusCode.INVALID_ARGUMENT:
      case StatusCode.OK:
      case StatusCode.CANCELLED:
      case StatusCode.UNKNOWN:
      case StatusCode.DEADLINE_EXCEEDED:
      case StatusCode.NOT_FOUND:
      case StatusCode.ALREADY_EXISTS:
      case StatusCode.PERMISSION_DENIED:
      case StatusCode.RESOURCE_EXHAUSTED:
      case StatusCode.FAILED_PRECONDITION:
      case StatusCode.ABORTED:
      case StatusCode.OUT_OF_RANGE:
      case StatusCode.UNIMPLEMENTED:
      case StatusCode.INTERNAL:
      case StatusCode.DATA_LOSS:
      case StatusCode.UNAUTHENTICATED:
      default:
        return new CallServiceError(rpcError, svcName);
    }
  } else {
    return e;
  }
}
