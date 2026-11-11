import { bootstrapApplication } from "@angular/platform-browser";
import { provideZonelessChangeDetection } from "@angular/core";
import { provideHttpClient, withInterceptors } from "@angular/common/http";
import { provideRouter } from "@angular/router";
import { AppComponent } from "./app";
bootstrapApplication(AppComponent, {
  providers: [
    provideZonelessChangeDetection(),
    provideHttpClient(
      withInterceptors([
        (req, next) =>
          next(
            req.clone({
              withCredentials: true,
              setHeaders: { "X-SellEase": "1" },
            }),
          ),
      ]),
    ),
    provideRouter([]),
  ],
}).catch(console.error);
