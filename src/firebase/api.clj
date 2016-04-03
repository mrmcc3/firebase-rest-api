(ns firebase.api
  (:refer-clojure :exclude [get set update])
  (:require [cheshire.core :as json]
            [clojure.string :as string]
            [buddy.sign.jws :as jws]
            [buddy.sign.util :refer [to-timestamp]]
            [clj-time.core :as time])
  (:import [javax.ws.rs.client ClientBuilder Entity]
           [javax.ws.rs.core MediaType]
           [org.glassfish.jersey.client ClientConfig]
           [org.glassfish.jersey.media.sse EventSource EventListener SseFeature]))

;; -----------------------------------------------------------------------------
;; Firebase Token Generator
;; see https://www.firebase.com/docs/rest/guide/user-auth.html#section-token-generation
;; and buddy-sign https://funcool.github.io/buddy-sign/latest/

(defn token
  "generates a firebase JWT. (generated JWT must be less than 1024 characters)
  nil is returned if requirements aren't met

  (Required args)
  uid is a unique identifier (must be lest than 256 characters)
  data is a map (accessible in firebase rules as auth. not encrypted!)
  secret is a firebase secret used to sign the JWT

  (Optional keyword args)
  exp is the number of hours (from time of generation) until the JWT expires (default 24 hours)
  nbf is the number of hours (from time of generation) until the JWT is valid (default is 0)
  admin if true grants complete read/write access to the entire firebase (default is false)
  debug if true enables debug mode (more verbose error messages) (default is false)
  "
  [uid data secret & {:keys [exp nbf admin debug]}]
  (let [now (time/now)
        add-hours #(to-timestamp (time/plus %1 (time/hours %2)))
        payload {:v 0 :d (assoc data :uid uid) :iat (to-timestamp now)}
        token (when (< (count uid) 256)
                (cond-> payload
                  exp (assoc :exp (add-hours now exp))
                  nbf (assoc :nbf (add-hours now nbf))
                  admin (assoc :admin true)
                  debug (assoc :debug true)
                  true (jws/sign secret)))]
    (when (< (count token) 1024) token)))

;; -----------------------------------------------------------------------------
;; helpers

(defn fb-path [xs]
  (str (string/join "/" (map #(if (keyword? %) (name %) %) xs)) ".json"))

(defn split-path [s]
  (case s "/" [] (string/split (subs s 1) #"/")))

;; -----------------------------------------------------------------------------
;; http client for Firebase REST API
;; (https://www.firebase.com/docs/rest/api/#section-api-usage)

(defn rest-client [root-url auth]
  (-> (ClientConfig.)
      (ClientBuilder/newClient)
      (.target root-url)
      (.queryParam "auth" (into-array Object [auth]))))

(defn get [client path]
  (-> client (.path (fb-path path)) .request
      .get (.readEntity String) (json/decode true)))

(defn set [client path value]
  (-> client (.path (fb-path path)) .request
      (.put (Entity/entity (json/encode value) (MediaType/APPLICATION_JSON)))
      (.readEntity String) (json/decode true)))

(defn push [client path value]
  (-> client (.path (fb-path path)) .request
      (.post (Entity/entity (json/encode value) (MediaType/APPLICATION_JSON)))
      (.readEntity String) (json/decode true)))

(defn update [client path value]
  (-> client (.path (fb-path path)) .request
      (.header "X-HTTP-Method-Override" "PATCH")
      (.post (Entity/entity (json/encode value) (MediaType/APPLICATION_JSON)))
      (.readEntity String) (json/decode true)))

;; -----------------------------------------------------------------------------
;; streaming client (via SSE) for Firebase REST API
;; https://www.firebase.com/docs/rest/api/#section-streaming

(defn streaming-client [root-url path auth]
  (-> (ClientBuilder/newBuilder)
      (.register SseFeature) .build
      (.target root-url)
      (.path (fb-path path))
      (.queryParam "auth" (into-array Object [auth]))
      EventSource/target .build))

(defn open [client]
  (.open client))

(defn close [client]
  (.close client))

(defn on-event [client cb]
  (let [el (reify EventListener
             (onEvent [_ e]
               (let [data (json/decode (.readData e) true)]
                 (cb {:name (keyword (.getName e))
                      :data (clojure.core/update data :path split-path)}))))]
    (.register client el)))

;; -----------------------------------------------------------------------------
;; Example Usage

(comment

  ;; config + token generation
  (def fb-url "https://<firebase name>.firebaseio.com")
  (def secret "<firebase-secret>")
  (def auth (token "test-uid" {:some "data"} secret :admin true))

  ;; realtime server sent events
  (def scl (streaming-client fb-url [] auth))
  (on-event scl #(println %))
  (open scl)
  (close scl)

  ;; basic firebase operations
  (def cl (rest-client fb-url auth))
  (set cl [:test] {:hello "world"})
  (get cl [:test :hello])
  (push cl [:test] "child")
  (update cl [:test] {:hello "again!"})
  (set cl [:test] nil)

  )
