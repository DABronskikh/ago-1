package app

import (
	"encoding/json"
	"github.com/DABronskikh/ago-1/cmd/service/app/dto"
	"github.com/DABronskikh/ago-1/cmd/service/app/middleware/authenticator"
	"github.com/DABronskikh/ago-1/cmd/service/app/middleware/identificator"
	"github.com/DABronskikh/ago-1/pkg/business"
	"github.com/DABronskikh/ago-1/pkg/security"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"log"
	"net/http"
)

type Server struct {
	securitySvc *security.Service
	businessSvc *business.Service
	mux         chi.Router
}

func NewServer(securitySvc *security.Service, businessSvc *business.Service, mux chi.Router) *Server {
	return &Server{securitySvc: securitySvc, businessSvc: businessSvc, mux: mux}
}

func (s *Server) Init() error {
	identificatorMd := identificator.Identificator
	authenticatorMd := authenticator.Authenticator(identificator.Identifier, s.securitySvc.UserDetails)

	s.mux.With(middleware.Logger).Post("/api/users", s.register)
	s.mux.With(middleware.Logger).Post("/tokens", s.token)
	s.mux.With(middleware.Logger, identificatorMd, authenticatorMd).Post("/cards", s.getCards)

	return nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.mux.ServeHTTP(writer, request)
}

func (s *Server) token(writer http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)
	user := &dto.UserDTO{}
	err := decoder.Decode(user)
	if err != nil {
		log.Println(err)
		data := &dto.ErrDTO{Err: err.Error()}
		prepareResponse(writer, data, http.StatusBadRequest)
		return
	}

	login := user.Login
	if login == "" {
		log.Println(security.ErrRequiredLogin)
		data := &dto.ErrDTO{Err: security.ErrRequiredLogin.Error()}
		prepareResponse(writer, data, http.StatusBadRequest)
		return
	}

	password := user.Password
	if password == "" {
		log.Println(security.ErrRequiredPass)
		data := &dto.ErrDTO{Err: security.ErrRequiredPass.Error()}
		prepareResponse(writer, data, http.StatusBadRequest)
		return
	}

	token, err := s.securitySvc.Login(request.Context(), login, password)
	if err != nil {
		log.Println(err)
		data := &dto.ErrDTO{Err: err.Error()}
		prepareResponse(writer, data, http.StatusBadRequest)
		return
	}

	data := &dto.TokenDTO{Token: token}
	prepareResponse(writer, data, http.StatusCreated)
	return
}

func (s *Server) register(writer http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)
	user := &dto.UserDTO{}
	err := decoder.Decode(user)
	if err != nil {
		log.Println(err)
		data := &dto.ErrDTO{Err: err.Error()}
		prepareResponse(writer, data, http.StatusBadRequest)
		return
	}

	login := user.Login
	if login == "" {
		data := &dto.ErrDTO{Err: security.ErrRequiredLogin.Error()}
		prepareResponse(writer, data, http.StatusBadRequest)
		return
	}

	password := user.Password
	if password == "" {
		data := &dto.ErrDTO{Err: security.ErrRequiredPass.Error()}
		prepareResponse(writer, data, http.StatusBadRequest)
		return
	}

	id, err := s.securitySvc.Register(request.Context(), login, password)

	if err == security.ErrUserDuplication {
		log.Println(err)
		data := &dto.ErrDTO{Err: err.Error()}
		prepareResponse(writer, data, http.StatusInternalServerError)
		return
	}
	if err != nil {
		log.Println(err)
		data := &dto.ErrDTO{Err: err.Error()}
		prepareResponse(writer, data, http.StatusBadRequest)
		return
	}

	data := &dto.IdDTO{Id: *id}
	prepareResponse(writer, data, http.StatusCreated)
	return
}

func (s *Server) getCards(writer http.ResponseWriter, request *http.Request) {
	userDetails, err := authenticator.Authentication(request.Context())
	if err != nil {
		log.Println(err)
		data := &dto.ErrDTO{Err: err.Error()}
		prepareResponse(writer, data, http.StatusBadRequest)
		return
	}

	details, ok := userDetails.(*security.UserDetails)
	if !ok {
		return
	}

	if s.securitySvc.HasAnyRole(request.Context(), userDetails, security.RoleAdmin) {
		cardDB, err := s.securitySvc.GetCardsAdmin(request.Context())

		if err == security.ErrUserDuplication {
			log.Println(err)
			data := &dto.ErrDTO{Err: err.Error()}
			prepareResponse(writer, data, http.StatusInternalServerError)
			return
		}

		if err != nil {
			log.Println(err)
			data := &dto.ErrDTO{Err: err.Error()}
			prepareResponse(writer, data, http.StatusBadRequest)
			return
		}

		data := &dto.CardsDTO{Cards: cardDB}
		prepareResponse(writer, data, http.StatusOK)
		return
	}
	if s.securitySvc.HasAnyRole(request.Context(), userDetails, security.RoleUser) {
		cardDB, err := s.securitySvc.GetCardsUser(request.Context(), details.ID)
		if err == security.ErrUserDuplication {
			data := &dto.ErrDTO{Err: err.Error()}
			prepareResponse(writer, data, http.StatusInternalServerError)
			return
		}
		if err != nil {
			log.Println(err)
			data := &dto.ErrDTO{Err: err.Error()}
			prepareResponse(writer, data, http.StatusBadRequest)
			return
		}

		data := &dto.CardsDTO{Cards: cardDB}
		prepareResponse(writer, data, http.StatusOK)
		return
	}

	log.Println(security.ErrNoAccess)
	data := &dto.ErrDTO{Err: security.ErrNoAccess.Error()}
	prepareResponse(writer, data, http.StatusForbidden)
	return
}

func prepareResponse(w http.ResponseWriter, dto interface{}, wHeader int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(wHeader)

	respBody, err := json.Marshal(dto)
	if err != nil {
		log.Println(err)
		return
	}

	_, err = w.Write(respBody)
	if err != nil {
		log.Println(err)
	}
}
