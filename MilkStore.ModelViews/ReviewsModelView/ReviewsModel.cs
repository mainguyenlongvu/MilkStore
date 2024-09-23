using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ReviewsModelView
{
    public class ReviewsModel
    {
        public string UserID { get; set; }
        public string ProductID { get; set; }
        [Required(ErrorMessage = "Rating không được để trống")]
        public required int Rating { get; set; }
        [Required(ErrorMessage = "Comment không được để trống")]
        public required string Comment { get; set; }
    }
}
