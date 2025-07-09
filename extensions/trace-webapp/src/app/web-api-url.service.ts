import { Injectable } from "@angular/core";
import { environment } from "./../environments/environment";

@Injectable({
  providedIn: "root"
})
export class WebApiUrlService {
  private _baseUrl: string;

  public get baseUrl(): string {
    return this._baseUrl;
  }

  getWebApiUrl(): string {
    return this._baseUrl;
  }

  constructor() {
    this._baseUrl = environment.webApiUrl;
    console.debug(`environment.baseUrl: ${this._baseUrl}`);
  }
}
