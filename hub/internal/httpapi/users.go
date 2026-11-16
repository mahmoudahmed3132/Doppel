// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

// UserStore is the persistence the users API needs (implemented by *store.DB).
type UserStore interface {
	ListUsers(ctx context.Context) ([]store.User, error)
	SetUserRole(ctx context.Context, id, role string) error
	SetUserDisabled(ctx context.Context, id string, disabled bool) error
	DeleteUser(ctx context.Context, id string) error
}

func (a *Admin) userFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		Fail(w, http.StatusNotFound, "not_found", "no such user")
	case errors.Is(err, store.ErrLastAdmin):
		Fail(w, http.StatusConflict, "last_admin", err.Error())
	case errors.Is(err, store.ErrProtectedUser):
		Fail(w, http.StatusForbidden, "protected_user", err.Error())
	case errors.Is(err, store.ErrBadRole):
		Fail(w, http.StatusUnprocessableEntity, CodeInvalid, err.Error())
	default:
		a.Log.Error("users", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "internal error")
	}
}

func (a *Admin) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := a.Users.ListUsers(r.Context())
	if err != nil {
		a.userFail(w, err)
		return
	}
	OK(w, map[string]any{"users": us})
}

// updateUser changes a role and/or the disabled flag. Either field may be
// omitted. Both changes are applied in order; the first failure stops.
func (a *Admin) updateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Role == nil && req.Disabled == nil {
		Fail(w, http.StatusUnprocessableEntity, CodeInvalid, "role or disabled is required")
		return
	}
	id := r.PathValue("id")
	if req.Role != nil {
		if err := a.Users.SetUserRole(r.Context(), id, *req.Role); err != nil {
			a.userFail(w, err)
			return
		}
	}
	if req.Disabled != nil {
		if err := a.Users.SetUserDisabled(r.Context(), id, *req.Disabled); err != nil {
			a.userFail(w, err)
			return
		}
	}
	OK(w, nil)
}

func (a *Admin) deleteUser(w http.ResponseWriter, r *http.Request) {
	if err := a.Users.DeleteUser(r.Context(), r.PathValue("id")); err != nil {
		a.userFail(w, err)
		return
	}
	OK(w, nil)
}
