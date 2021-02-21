import { Injectable } from '@angular/core';
import { AccountService } from '../_services/account.service';
import { map } from 'rxjs/operators';
import { ToastrService } from 'ngx-toastr';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, UrlTree } from '@angular/router';
import { Observable } from 'rxjs';

@Injectable({
    providedIn: 'root'
})
export class AuthGuard implements CanActivate {
    constructor(private accountService:AccountService , private  toastr:ToastrService){}

    canActivate(): Observable<boolean>{
        return this.accountService.currentUser$.pipe(
            map( user => {
                if (user) return true;
                else {
                    this.toastr.error("You shall not pass");
                    return false;
                }
            })
        );
    }

}
