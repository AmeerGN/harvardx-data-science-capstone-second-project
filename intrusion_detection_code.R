# Intrusion Detection System (IDS) Project
# Author: Ameer Nasrallah

##########################################################
# Create train set, test set (final hold-out test set)
##########################################################
if(!require(tidyverse)) install.packages("tidyverse", repos = "http://cran.us.r-project.org")
if(!require(caret)) install.packages("caret", repos = "http://cran.us.r-project.org")
if(!require(recipes)) install.packages("recipes", repos = "http://cran.us.r-project.org")
if(!require(doParallel)) install.packages("doParallel", repos = "http://cran.us.r-project.org")

library(tidyverse)
library(caret)
library(recipes)
library(doParallel)

basic_features <- c("duration",
                    "protocol_type",
                    "service",
                    "flag",
                    "src_bytes",
                    "dst_bytes",
                    "land",
                    "wrong_fragment",
                    "urgent")

content_features <- c("hot",
                      "num_failed_logins",
                      "logged_in",
                      "num_compromised",
                      "root_shell",
                      "su_attempted",
                      "num_root",
                      "num_file_creations",
                      "num_shells",
                      "num_access_files",
                      "num_outbound_cmds",
                      "is_host_login",
                      "is_guest_login")

time_based_traffic_features <- c("count",
                                 "srv_count",
                                 "serror_rate",
                                 "srv_serror_rate",
                                 "rerror_rate",
                                 "srv_rerror_rate",
                                 "same_srv_rate",
                                 "diff_srv_rate",
                                 "srv_diff_host_rate")

host_based_traffic_features <- c("dst_host_count",
                                 "dst_host_srv_count",
                                 "dst_host_same_srv_rate",
                                 "dst_host_diff_srv_rate",
                                 "dst_host_same_src_port_rate",
                                 "dst_host_srv_diff_host_rate",
                                 "dst_host_serror_rate",
                                 "dst_host_srv_serror_rate",
                                 "dst_host_rerror_rate",
                                 "dst_host_srv_rerror_rate")

attr_names <- c(basic_features, content_features, time_based_traffic_features, host_based_traffic_features)
col_names <- c(attr_names, "label", "difficulty")

if (file.exists("data/NSL-KDD.RData")) {
  load("data/NSL-KDD.RData")
} else {
  nsl_kdd_test_csv = read.csv(file = "https://github.com/jmnwong/NSL-KDD-Dataset/raw/master/KDDTest%2B.txt", col.names = col_names, header = FALSE)
  nsl_kdd_train_csv = read.csv(file = "https://github.com/jmnwong/NSL-KDD-Dataset/raw/master/KDDTrain%2B.txt", col.names = col_names, header = FALSE)
  save(nsl_kdd_train_csv, nsl_kdd_test_csv, file = "data/NSL-KDD.RData")
}

str(nsl_kdd_train_csv)

summary(nsl_kdd_train_csv)

# Remove difficulty column
nsl_kdd_train_csv <- nsl_kdd_train_csv %>%
                        select(-difficulty)
nsl_kdd_test_csv <- nsl_kdd_test_csv %>%
                        select(-difficulty)

# Add multi library and binary library
normal_label = "normal"
dos_attacks = c("neptune", "back", "land", "pod", "smurf", "teardrop", "mailbomb", "apache2", "processtable", "udpstorm", "worm")
probing_attacks = c("ipsweep", "nmap", "portsweep", "satan", "mscan", "saint")
r2l_attacks = c("ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient", "warezmaster", "sendmail", "named", "snmpgetattack", "snmpguess", "xlock", "xsnoop", "httptunnel")
u2r_attacks = c("buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack", "xterm")

label_to_multi_category <- function(label) {
  if (label == normal_label) {
    return(0)
  } else if (label %in% dos_attacks) {
    return(1)
  } else if (label %in% probing_attacks) {
    return(2)
  } else if (label %in% r2l_attacks) {
    return(3)
  } else if (label %in% u2r_attacks) {
    return(4)
  }
}

nsl_kdd_train_csv <- nsl_kdd_train_csv %>%
                      mutate(multi_label = sapply(label, label_to_multi_category), binary_label = ifelse(multi_label == 0, 0, 1)) %>%
                      select(-label)
nsl_kdd_train_csv$binary_label <- factor(nsl_kdd_train_csv$binary_label)
nsl_kdd_train_csv$multi_label <- factor(nsl_kdd_train_csv$multi_label)
nsl_kdd_test_csv <- nsl_kdd_test_csv %>%
                      mutate(multi_label = sapply(label, label_to_multi_category), binary_label = ifelse(multi_label == 0, 0, 1)) %>%
                      select(-label)
nsl_kdd_test_csv$binary_label <- factor(nsl_kdd_test_csv$binary_label)
nsl_kdd_test_csv$multi_label <- factor(nsl_kdd_test_csv$multi_label)

rm(normal_label, dos_attacks, probing_attacks, r2l_attacks, u2r_attacks, label_to_multi_category)
rm(attr_names, basic_features, col_names, content_features, host_based_traffic_features, time_based_traffic_features)

##########################################################
# Normalize PDF Recipe Step Definition
# References: http://cran.nexr.com/web/packages/recipes/vignettes/Custom_Steps.html
#             https://github.com/tidymodels/recipes/blob/main/R/center.R
##########################################################

step_nominalpdf <-
  function(recipe,
           ..., 
           role = NA,
           trained = FALSE,
           ref_dist = NULL,
           skip = FALSE,
           id = rand_id("nominalpdf")) {
    add_step(
      recipe, 
      step_nominalpdf_new(
        terms = enquos(...), 
        trained = trained,
        role = role, 
        ref_dist = ref_dist,
        skip = skip,
        id = id
      )
    )
  }

step_nominalpdf_new <-
  function(terms, role, trained, ref_dist, skip, id) {
    step(
      subclass = "nominalpdf", 
      terms = terms,
      role = role,
      trained = trained,
      ref_dist = ref_dist,
      skip = skip,
      id = id
    )
  }

prep.step_nominalpdf <- function(x, training, info = NULL, ...) {
  col_names <- recipes_eval_select(x$terms, training, info)
  
  ref_dist <- list()
  train_ln <- nrow(training)
  for (i in col_names) {
    ref_dist[[i]] <- table(training[, i]) / train_ln
  }
  
  ## Always return the updated step
  step_nominalpdf_new(
    terms = x$terms,
    role = x$role,
    trained = TRUE,
    ref_dist = ref_dist,
    skip = x$skip,
    id = x$id
  )
}

pdf_by_ref <- function(x, ref) {
  ifelse(x %in% names(ref), ref[x][[1]], 0)
}

bake.step_nominalpdf <- function(object, new_data, ...) {
  require(tibble)
  ## For illustration (and not speed), we will loop through the affected variables
  ## and do the computations
  vars <- names(object$ref_dist)
  
  for(i in vars) {
    new_data[, i] <- apply(new_data[, i], 1, pdf_by_ref, ref = object$ref_dist[[i]])
  }
  ## Always convert to tibbles on the way out
  tibble::as_tibble(new_data)
}

print.step_nominalpdf <- function(x, width = max(20, options()$width - 30), ...) {
  cat("PDF for ", sep = "")
  printer(names(x$ref_dist), x$terms, x$trained, width = width)
  invisible(x)
}

tidy.step_nominalpdf <- function(x, ...) {
  if (is_trained(x)) {
    res <- tibble(terms = names(x$ref_dist),
                  value = unname(x$ref_dist))
  } else {
    term_names <- sel2char(x$terms)
    res <- tibble(terms = term_names,
                  value = na_dbl)
  }
  res$id <- x$id
  res
}

##########################################################
# Define the recipe for multi-label data
##########################################################

cluster = makePSOCKcluster(detectCores() - 2) # Create a cluster
registerDoParallel(cluster)
clusterExport(cl=cluster, varlist=c("step_nominalpdf", "step_nominalpdf_new", "prep.step_nominalpdf", "pdf_by_ref", "bake.step_nominalpdf", "print.step_nominalpdf", "tidy.step_nominalpdf"), envir=environment())
set.seed(1, sample.kind="Rounding") # if using R 3.5 or earlier, use `set.seed(1)`s
nsl_kdd_train_csv_multi <- nsl_kdd_train_csv %>% select(-binary_label)
nsl_kdd_test_csv_multi <- nsl_kdd_test_csv %>% select(-binary_label)
nsl_kdd_csv_multi_rec <- recipe(multi_label ~ ., data = nsl_kdd_train_csv_multi) %>%
                          step_nominalpdf(all_nominal_predictors()) %>%
                          step_range(all_numeric_predictors(), -land, -logged_in, -is_host_login, -is_guest_login)
sbf_binary_fit <- sbf(x = nsl_kdd_csv_multi_rec,
                      data = nsl_kdd_train_csv_multi,
                      method = "svmLinear",
                      tuneGrid = data.frame(C = 1),
                      trControl = trainControl(),
                      sbfControl = sbfControl(functions = caretSBF, saveDetails = TRUE, verbose = TRUE, number = 20, method = "LGOCV"))
stopCluster(cluster)

##########################################################
# Define the recipe for binary-label data
##########################################################

cluster = makePSOCKcluster(detectCores() - 2) # Create a cluster
registerDoParallel(cluster)
clusterExport(cl=cluster, varlist=c("step_nominalpdf", "step_nominalpdf_new", "prep.step_nominalpdf", "pdf_by_ref", "bake.step_nominalpdf", "print.step_nominalpdf", "tidy.step_nominalpdf"), envir=environment())
set.seed(1, sample.kind="Rounding") # if using R 3.5 or earlier, use `set.seed(1)`
nsl_kdd_train_csv_binary <- nsl_kdd_train_csv %>% select(-multi_label)
nsl_kdd_test_csv_binary <- nsl_kdd_test_csv %>% select(-multi_label)
nsl_kdd_csv_binary_rec <- recipe(binary_label ~ ., data = nsl_kdd_train_csv_binary) %>%
                              step_nominalpdf(all_nominal_predictors()) %>%
                              step_range(all_numeric_predictors(), -land, -logged_in, -is_host_login, -is_guest_login)
library(naivebayes)
sbf_binary_fit <- sbf(x = nsl_kdd_csv_binary_rec,
             data = nsl_kdd_train_csv_binary,
             method = "naive_bayes",
             trControl = trainControl(method = "cv", seeds = sample.int(200000, 11)),
             sbfControl = sbfControl(functions = caretSBF, saveDetails = TRUE, method = "cv", seeds = sample.int(100000, 11)))
binary_preds <- predict(sbf_binary_fit, nsl_kdd_test_csv_binary)
confusionMatrix(binary_preds$pred, nsl_kdd_test_csv_binary$binary_label)$overall["Accuracy"][[1]]
stopCluster(cluster)


# Other classifiers: glm, lda, qda, gamLoess, rf
# sensitivity(factor(kmeans_preds), test_y, positive = "B")
# sensitivity(factor(kmeans_preds), test_y, positive = "M")
# fit_rf$bestTune
# varImp(fit_rf)